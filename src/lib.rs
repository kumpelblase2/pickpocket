use log::{debug, info, LevelFilter};
use once_cell::sync::OnceCell;
use retour::static_detour;
use std::ffi::c_void;
use std::fmt::{Display, Formatter};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::{env, mem};
use windows::core::s;
use windows::Win32::Foundation::*;
use windows::Win32::System::Console::AllocConsole;
use windows::Win32::System::SystemServices::*;
use windows::Win32::System::Threading::CreateMutexA;

fn address_from_env(env: &str, address: usize) -> usize {
    env::var(env).ok().and_then(|v| v.parse().ok()).unwrap_or(address)
}

const OPCODE_SET_FN: usize = 0x00686300;
const PACKET_SEND_FN: usize = 0x00686680;
const PACKET_WRITE_FN: usize = 0x005f7a00;
const OPEN_AD_FN: usize = 0x00676bf0;
const PACKET_READ_FN: usize = 0x005f1fb0;
const PACKET_ACCEPT_FN: usize = 0x00bb28d0;

type SetOpcodeFn = fn(u16, u32);
type SendPacketFn = fn(*mut c_void);
type WriteDataFn = unsafe extern "thiscall" fn(*mut c_void, *const u32, usize);
type OpenAdFn = unsafe extern "fastcall" fn(u32);
type ReadDataFn = unsafe extern "thiscall" fn(*mut c_void, *mut u8, usize) -> usize;
type PacketAcceptFn = unsafe extern "thiscall" fn(*mut c_void, *const PacketData) -> u32;

static_detour! {
    static SetOpcodeDetour: fn(u16, u32);
    static SendPacketDetour: fn(*mut c_void);
    static WriteDetour: unsafe extern "thiscall" fn(*mut c_void, *const u32, usize);
    static OpenAdDetour: unsafe extern "fastcall" fn(u32);
    static ReadDataDetour: unsafe extern "thiscall" fn(*mut c_void, *mut u8, usize) -> usize;
    static PacketAcceptDetour: unsafe extern "thiscall" fn(*mut c_void, *const PacketData) -> u32;
}

#[repr(C)]
struct PacketData {
    _unknown: [u8; 24],
    opcode: u16,
}

static PACKET_RECORDER: OnceCell<Mutex<PacketRecorder>> = OnceCell::new();

enum Direction {
    ToServer,
    ToClient,
}

impl Display for Direction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Direction::ToServer => write!(f, "C->S"),
            Direction::ToClient => write!(f, "S->C"),
        }
    }
}

struct PacketInProcess {
    direction: Direction,
    opcode: u16,
    data: Vec<Vec<u8>>,
}

impl PacketInProcess {
    pub fn new(opcode: u16, direction: Direction) -> Self {
        Self {
            opcode,
            direction,
            data: Vec::new(),
        }
    }

    fn record(&mut self, data: Vec<u8>) {
        self.data.push(data);
    }
}

struct PacketRecorder {
    file: File,
    current_write_packet: Option<PacketInProcess>,
    current_read_packet: Option<PacketInProcess>,
}

impl PacketRecorder {
    fn start_writing_packet(&mut self, opcode: u16) {
        if self.current_write_packet.is_none() {
            self.current_write_packet = Some(PacketInProcess::new(opcode, Direction::ToServer));
        }
    }

    fn start_reading_packet(&mut self, opcode: u16) {
        if self.current_read_packet.is_none() {
            self.current_read_packet = Some(PacketInProcess::new(opcode, Direction::ToClient));
        }
    }

    fn record_written_data(&mut self, data: Vec<u8>) {
        if let Some(packet) = self.current_write_packet.as_mut() {
            packet.record(data);
        }
    }

    fn record_read_data(&mut self, data: Vec<u8>) {
        if let Some(packet) = self.current_read_packet.as_mut() {
            packet.record(data);
        }
    }

    fn finish_current_writing_packet(&mut self) {
        if let Some(packet) = self.current_write_packet.take() {
            self.write_packet(packet)
                .expect("Should be able to write packet to file");
        }
    }

    fn finish_current_read_packet(&mut self) {
        if let Some(packet) = self.current_read_packet.take() {
            self.write_packet(packet)
                .expect("Should be able to write packet to file");
        }
    }

    fn write_packet(&mut self, packet: PacketInProcess) -> std::io::Result<()> {
        self.file
            .write(format!("[{}] {:x}", packet.direction, packet.opcode).as_bytes())?;
        self.file.write(b"\t")?;
        for data in packet.data {
            self.file.write(
                format!(
                    "[{}]",
                    data.iter().map(|b| format!("{:x}", b)).collect::<Vec<_>>().join(" ")
                )
                .as_bytes(),
            )?;
        }
        self.file.write(b"\n")?;
        self.file.flush()?;
        Ok(())
    }
}

fn init_recorder() -> Mutex<PacketRecorder> {
    let target_path = Path::new("packets.txt");

    let f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(target_path)
        .expect("Should be able to open file");

    let recorder = PacketRecorder {
        file: f,
        current_write_packet: None,
        current_read_packet: None,
    };

    Mutex::new(recorder)
}

fn on_packet_create(opcode: u16, is_finished: u32) {
    if is_finished == 0 {
        info!("Starting packet with opcode {:x}", opcode);
        debug!(
            "Are we still in the process of sending another packet? {}",
            WriteDetour.is_enabled()
        );
        PACKET_RECORDER
            .get_or_init(init_recorder)
            .lock()
            .expect("Should be able to lock packet recorder")
            .start_writing_packet(opcode);
        unsafe {
            WriteDetour.enable().expect("Should be able to enable write detour.");
        }
    } else {
        info!("Finished packet with opcode {:x}", opcode);
        PACKET_RECORDER
            .get_or_init(init_recorder)
            .lock()
            .expect("Should be able to lock packet recorder")
            .finish_current_writing_packet();
        unsafe {
            WriteDetour.disable().expect("Should be able to enable write detour.");
        }
    }

    SetOpcodeDetour.call(opcode, is_finished)
}

fn on_packet_send(packet: *mut c_void) {
    debug!("Packet has been sent.");
    unsafe {
        WriteDetour.disable().expect("Should be able to disable detour.");
        SendPacketDetour.call(packet);
    }
}

fn on_data_written(packet: *mut c_void, content: *const u32, size: usize) {
    debug!("Writing {} bytes.", size);

    let mut target = vec![0u8; size];
    unsafe {
        std::ptr::copy_nonoverlapping(mem::transmute(content), target.as_mut_ptr(), size);
    }

    PACKET_RECORDER
        .get_or_init(init_recorder)
        .lock()
        .expect("Should be able to lock packet recorder")
        .record_written_data(target);

    unsafe {
        WriteDetour.call(packet, content, size);
    }
}

fn on_open_ad(_unknown: u32) {
    // Do nothing - we don't care.
}

fn on_read_bytes(packet: *mut c_void, dest: *mut u8, length: usize) -> usize {
    let read = unsafe { ReadDataDetour.call(packet, dest, length) };
    debug!("Trying to read {} bytes.", length);
    let mut data = vec![0; read];
    unsafe {
        std::ptr::copy_nonoverlapping(dest, data.as_mut_ptr(), read);
    }
    let mut recorder = PACKET_RECORDER
        .get_or_init(init_recorder)
        .lock()
        .expect("Should be able to lock mutex.");
    recorder.record_read_data(data);

    return read;
}

fn on_packet_accept(packet: *mut c_void, data: *const PacketData) -> u32 {
    let opcode = unsafe { (*data).opcode };
    info!("Accepting packet, opcode: {:x}", opcode);
    {
        PACKET_RECORDER
            .get_or_init(init_recorder)
            .lock()
            .expect("Should be able to lock mutex.")
            .start_reading_packet(opcode);
    }
    unsafe {
        ReadDataDetour.enable().expect("Should be able to enable read detour");
        let result = PacketAcceptDetour.call(packet, data);
        ReadDataDetour.disable().expect("Should be able to enable read detour");
        {
            PACKET_RECORDER
                .get_or_init(init_recorder)
                .lock()
                .expect("Should be able to lock mutex.")
                .finish_current_read_packet();
        }
        result
    }
}

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    match call_reason {
        DLL_PROCESS_ATTACH => attach(),
        DLL_PROCESS_DETACH => detach(),
        _ => true,
    }
}

fn setup_logging() {
    unsafe {
        AllocConsole().expect("Should be able to allocation the console.");
    }

    simple_logging::log_to(std::io::stdout(), LevelFilter::Trace);
}

fn init_mutexes() {
    unsafe {
        CreateMutexA(None, false, s!("Silkroad Online Launcher")).expect("Should be able to create launcher mutex");
        CreateMutexA(None, false, s!("Ready")).expect("Should be able to create ready mutex");
    }
    debug!("Setup mutexes to bypass launcher check.");
}

fn should_skip_ad() -> bool {
    if let Ok(v) = env::var("SKIP_AD") {
        v.parse().ok().unwrap_or(true)
    } else {
        true
    }
}

fn init_detours() {
    unsafe {
        init_opcode_set_detour();
        // init_packet_send_detour();
        init_packet_write_detour();
        init_packet_read_detour();
        init_packet_accept_detour();
        if should_skip_ad() {
            init_skip_ad_detour();
        }
    }
}

unsafe fn init_skip_ad_detour() {
    let target: OpenAdFn = mem::transmute(address_from_env("AD_OPEN_ADDRESS", OPEN_AD_FN));
    OpenAdDetour
        .initialize(target, on_open_ad)
        .expect("Should be able to initialize ad detour");
    OpenAdDetour.enable().expect("Should be able to enable ad detour.");
}

unsafe fn init_packet_write_detour() {
    let target: WriteDataFn = mem::transmute(address_from_env("PACKET_WRITE_ADDRESS", PACKET_WRITE_FN));
    WriteDetour
        .initialize(target, on_data_written)
        .expect("Should be able to initialize write detour");
}

unsafe fn init_packet_send_detour() {
    let target: SendPacketFn = mem::transmute(address_from_env("PACKET_SEND_ADDRESS", PACKET_SEND_FN));
    SendPacketDetour
        .initialize(target, on_packet_send)
        .expect("Should be able to initialize send detour");
    SendPacketDetour.enable().expect("Should be able to enable send detour");
}

unsafe fn init_opcode_set_detour() {
    let target: SetOpcodeFn = mem::transmute(address_from_env("PACKET_OPCODE_ADDRESS", OPCODE_SET_FN));
    SetOpcodeDetour
        .initialize(target, on_packet_create)
        .expect("Should be able to initialize opcode detour");
    SetOpcodeDetour
        .enable()
        .expect("Should be able to enable opcode detour");
}

unsafe fn init_packet_read_detour() {
    let target: ReadDataFn = mem::transmute(address_from_env("PACKET_READ_ADDRESS", PACKET_READ_FN));
    ReadDataDetour
        .initialize(target, on_read_bytes)
        .expect("Should be able to initialize read detour");
}

unsafe fn init_packet_accept_detour() {
    let target: PacketAcceptFn = mem::transmute(address_from_env("PACKET_ACCEPT_ADDRESS", PACKET_ACCEPT_FN));
    PacketAcceptDetour
        .initialize(target, on_packet_accept)
        .expect("Should be able to initialize read detour");
    PacketAcceptDetour
        .enable()
        .expect("Should be able to enable accept detour.");
}

fn attach() -> bool {
    setup_logging();
    info!("Successfully injected.");
    init_recorder();
    init_mutexes();
    init_detours();
    info!("Detours set up, waiting for packets.");
    true
}

fn detach() -> bool {
    true
}
