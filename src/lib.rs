use log::{debug, info, LevelFilter};
use once_cell::sync::OnceCell;
use retour::static_detour;
use std::ffi::c_void;
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

const OPCODE_SET_FN: usize = 0x00686300;
const PACKET_SEND_FN: usize = 0x00686680;
const PACKET_WRITE_FN: usize = 0x005f7a00;
const OPEN_AD_FN: usize = 0x00676bf0;

type SetOpcodeFn = fn(u16, u32);
type SendPacketFn = fn(*mut c_void);
type WriteDataFn = unsafe extern "thiscall" fn(*mut c_void, *const u32, usize);
type OpenAdFn = unsafe extern "fastcall" fn(u32);

static_detour! {
    static SetOpcodeDetour: fn(u16, u32);
    static SendPacketDetour: fn(*mut c_void);
    static WriteDetour: unsafe extern "thiscall" fn(*mut c_void, *const u32, usize);
    static OpenAdDetour: unsafe extern "fastcall" fn(u32);
}

static PACKET_RECORDER: OnceCell<Mutex<PacketRecorder>> = OnceCell::new();

struct PacketInProcess {
    opcode: u16,
    data: Vec<Vec<u8>>,
}

impl PacketInProcess {
    pub fn new(opcode: u16) -> Self {
        Self {
            opcode,
            data: Vec::new(),
        }
    }

    fn record(&mut self, data: Vec<u8>) {
        self.data.push(data);
    }
}

struct PacketRecorder {
    file: File,
    current_packet: Option<PacketInProcess>,
}

impl PacketRecorder {
    fn start_packet(&mut self, opcode: u16) {
        if self.current_packet.is_none() {
            self.current_packet = Some(PacketInProcess::new(opcode));
        }
    }

    fn record_data(&mut self, data: Vec<u8>) {
        if let Some(packet) = self.current_packet.as_mut() {
            packet.record(data);
        }
    }

    fn finish_current_packet(&mut self) {
        if let Some(packet) = self.current_packet.take() {
            self.write_packet(packet)
                .expect("Should be able to write packet to file");
        }
    }

    fn write_packet(&mut self, packet: PacketInProcess) -> std::io::Result<()> {
        self.file.write(format!("{:x}", packet.opcode).as_bytes())?;
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
        current_packet: None,
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
            .start_packet(opcode);
        unsafe {
            WriteDetour.enable().expect("Should be able to enable write detour.");
        }
    } else {
        info!("Finished packet with opcode {:x}", opcode);
        PACKET_RECORDER
            .get_or_init(init_recorder)
            .lock()
            .expect("Should be able to lock packet recorder")
            .finish_current_packet();
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
        .record_data(target);

    unsafe {
        WriteDetour.call(packet, content, size);
    }
}

fn on_open_ad(_unknown: u32) {
    // Do nothing - we don't care.
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
    env::var("skip_ad").unwrap_or(String::from("0")).parse().unwrap_or(true)
}

fn init_detours() {
    unsafe {
        init_opcode_set_detour();
        // init_packet_send_detour();
        init_packet_write_detour();
        if should_skip_ad() {
            init_skip_ad_detour();
        }
    }
}

unsafe fn init_skip_ad_detour() {
    let target: OpenAdFn = mem::transmute(OPEN_AD_FN);
    OpenAdDetour
        .initialize(target, on_open_ad)
        .expect("Should be able to initialize ad detour");
    OpenAdDetour.enable().expect("Should be able to enable ad detour.");
}

unsafe fn init_packet_write_detour() {
    let target: WriteDataFn = mem::transmute(PACKET_WRITE_FN);
    WriteDetour
        .initialize(target, on_data_written)
        .expect("Should be able to initialize write detour");
}

unsafe fn init_packet_send_detour() {
    let target: SendPacketFn = mem::transmute(PACKET_SEND_FN);
    SendPacketDetour
        .initialize(target, on_packet_send)
        .expect("Should be able to initialize send detour");
    SendPacketDetour.enable().expect("Should be able to enable send detour");
}

unsafe fn init_opcode_set_detour() {
    let target: SetOpcodeFn = mem::transmute(OPCODE_SET_FN);
    SetOpcodeDetour
        .initialize(target, on_packet_create)
        .expect("Should be able to initialize opcode detour");
    SetOpcodeDetour
        .enable()
        .expect("Should be able to enable opcode detour");
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
