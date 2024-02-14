use crate::data::{ClientMessage, Direction};
use ipc_channel::ipc::IpcSender;
use log::{debug, info, LevelFilter};
use once_cell::sync::OnceCell;
use retour::static_detour;
use std::ffi::c_void;
use std::io::Write;
use std::sync::Mutex;
use std::{env, mem};
use windows::core::s;
use windows::Win32::Foundation::*;
use windows::Win32::System::SystemServices::*;
use windows::Win32::System::Threading::CreateMutexA;

mod data;

fn address_from_env(env: &str, address: usize) -> usize {
    env::var(env)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(address)
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

static PACKET_RECORDER: OnceCell<Mutex<IpcSender<ClientMessage>>> = OnceCell::new();

fn init_recorder() -> Mutex<IpcSender<ClientMessage>> {
    let server = env::var("IPC_SERVER").expect("A ipc server should be set");
    let sender = IpcSender::connect(server).expect("Should be able to connect to server");

    Mutex::new(sender)
}

fn on_packet_create(opcode: u16, is_finished: u32) {
    if is_finished == 0 {
        info!("Starting packet with opcode {:x}", opcode);
        debug!(
            "Are we still in the process of sending another packet? {}",
            WriteDetour.is_enabled()
        );
        let _ = PACKET_RECORDER
            .get_or_init(init_recorder)
            .lock()
            .expect("Should be able to lock packet recorder")
            .send(ClientMessage::PacketStart(opcode, Direction::ToServer));
        unsafe { WriteDetour.enable() }.expect("Should be able to enable write detour.");
    } else {
        info!("Finished packet with opcode {:x}", opcode);
        let _ = PACKET_RECORDER
            .get_or_init(init_recorder)
            .lock()
            .expect("Should be able to lock packet recorder")
            .send(ClientMessage::PacketFinish(Direction::ToServer));
        unsafe { WriteDetour.disable() }.expect("Should be able to enable write detour.");
    }

    SetOpcodeDetour.call(opcode, is_finished)
}

fn on_packet_send(packet: *mut c_void) {
    debug!("Packet has been sent.");
    unsafe {
        WriteDetour
            .disable()
            .expect("Should be able to disable detour.");
        SendPacketDetour.call(packet);
    }
}

fn on_data_written(packet: *mut c_void, content: *const u32, size: usize) {
    debug!("Writing {} bytes.", size);

    let mut target = vec![0u8; size];
    unsafe {
        std::ptr::copy_nonoverlapping(mem::transmute(content), target.as_mut_ptr(), size);
    }

    let _ = PACKET_RECORDER
        .get_or_init(init_recorder)
        .lock()
        .expect("Should be able to lock packet recorder")
        .send(ClientMessage::PacketData(Direction::ToServer, target));

    unsafe {
        WriteDetour.call(packet, content, size);
    }
}

fn on_open_ad(_unknown: u32) {
    // Do nothing - we don't care.
}

fn on_read_bytes(packet: *mut c_void, dest: *mut u8, length: usize) -> usize {
    // SAFETY: We are defined as that detour and are simply forwarding the parameters.
    // As long as we have the parameters correct, this should simply be the original call
    // that we're replacing.
    let read = unsafe { ReadDataDetour.call(packet, dest, length) };
    debug!("Trying to read {} bytes.", length);
    let mut data = vec![0; read];
    // SAFETY: For the following, we're essentially just copying raw bytes. As such, we
    // don't need to worry much about alignment. We also made sure that the copy destination
    // (`data`) is at least of size `count * size_of::<u8>` above. We also know how much data
    // was actually written to the buffer, thus `dest` must be at least `read` large. We also
    // know that they don't overlap because we just created the vector anew.
    unsafe {
        std::ptr::copy_nonoverlapping(dest, data.as_mut_ptr(), read);
    }
    let mut recorder = PACKET_RECORDER
        .get_or_init(init_recorder)
        .lock()
        .expect("Should be able to lock mutex.");
    let _ = recorder.send(ClientMessage::PacketData(Direction::ToClient, data));

    return read;
}

fn on_packet_accept(packet: *mut c_void, data: *const PacketData) -> u32 {
    let opcode = unsafe { (*data).opcode };
    info!("Accepting packet, opcode: {:x}", opcode);
    {
        let _ = PACKET_RECORDER
            .get_or_init(init_recorder)
            .lock()
            .expect("Should be able to lock mutex.")
            .send(ClientMessage::PacketStart(opcode, Direction::ToClient));
    }
    unsafe {
        ReadDataDetour
            .enable()
            .expect("Should be able to enable read detour");
        let result = PacketAcceptDetour.call(packet, data);
        ReadDataDetour
            .disable()
            .expect("Should be able to enable read detour");
        {
            let _ = PACKET_RECORDER
                .get_or_init(init_recorder)
                .lock()
                .expect("Should be able to lock mutex.")
                .send(ClientMessage::PacketFinish(Direction::ToClient));
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

struct IpcLogger;

impl Write for IpcLogger {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        PACKET_RECORDER
            .get_or_init(init_recorder)
            .lock()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Mutex was poisoned"))?
            .send(ClientMessage::Log(Vec::from(buf)))
            .map_err(|er| std::io::Error::new(std::io::ErrorKind::Other, er))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn setup_logging() {
    simple_logging::log_to(IpcLogger, LevelFilter::Trace);
}

fn init_mutexes() {
    unsafe {
        CreateMutexA(None, false, s!("Silkroad Online Launcher"))
            .expect("Should be able to create launcher mutex");
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
    OpenAdDetour
        .enable()
        .expect("Should be able to enable ad detour.");
}

unsafe fn init_packet_write_detour() {
    let target: WriteDataFn =
        mem::transmute(address_from_env("PACKET_WRITE_ADDRESS", PACKET_WRITE_FN));
    WriteDetour
        .initialize(target, on_data_written)
        .expect("Should be able to initialize write detour");
}

unsafe fn init_packet_send_detour() {
    let target: SendPacketFn =
        mem::transmute(address_from_env("PACKET_SEND_ADDRESS", PACKET_SEND_FN));
    SendPacketDetour
        .initialize(target, on_packet_send)
        .expect("Should be able to initialize send detour");
    SendPacketDetour
        .enable()
        .expect("Should be able to enable send detour");
}

unsafe fn init_opcode_set_detour() {
    let target: SetOpcodeFn =
        mem::transmute(address_from_env("PACKET_OPCODE_ADDRESS", OPCODE_SET_FN));
    SetOpcodeDetour
        .initialize(target, on_packet_create)
        .expect("Should be able to initialize opcode detour");
    SetOpcodeDetour
        .enable()
        .expect("Should be able to enable opcode detour");
}

unsafe fn init_packet_read_detour() {
    let target: ReadDataFn =
        mem::transmute(address_from_env("PACKET_READ_ADDRESS", PACKET_READ_FN));
    ReadDataDetour
        .initialize(target, on_read_bytes)
        .expect("Should be able to initialize read detour");
}

unsafe fn init_packet_accept_detour() {
    let target: PacketAcceptFn =
        mem::transmute(address_from_env("PACKET_ACCEPT_ADDRESS", PACKET_ACCEPT_FN));
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
    init_mutexes();
    init_detours();
    info!("Detours set up, waiting for packets.");
    true
}

fn detach() -> bool {
    true
}
