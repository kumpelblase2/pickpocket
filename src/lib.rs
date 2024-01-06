use log::{debug, info, LevelFilter};
use retour::static_detour;
use std::ffi::c_void;
use std::{env, mem};
use windows::core::s;
use windows::Win32::Foundation::*;
use windows::Win32::System::Console::AllocConsole;
use windows::Win32::System::SystemServices::*;
use windows::Win32::System::Threading::CreateMutexA;

const OPCODE_SET_FN: usize = 0x005f5b10;
const PACKET_SEND_FN: usize = 0x00686680;
const PACKET_WRITE_FN: usize = 0x005f7a00;
const OPEN_AD_FN: usize = 0x00676bf0;

type SetOpcodeFn = unsafe extern "thiscall" fn(*mut c_void, u32) -> *mut c_void;
type SendPacketFn = fn(*mut c_void);
type WriteDataFn = unsafe extern "thiscall" fn(*mut c_void, *const u8, usize);
type OpenAdFn = unsafe extern "fastcall" fn(u32);

static_detour! {
    static SetOpcodeDetour: unsafe extern "thiscall" fn(*mut c_void, u32) -> *mut c_void;
    static SendPacketDetour: fn(*mut c_void);
    static WriteDetour: unsafe extern "thiscall" fn(*mut c_void, *const u8, usize);
    static OpenAdDetour: unsafe extern "fastcall" fn(u32);
}

fn on_packet_create(this: *mut c_void, op: u32) -> *mut c_void {
    info!("Starting packet with opcode {:x}", op);
    debug!(
        "Are we still in the process of sending another packet? {}",
        WriteDetour.is_enabled()
    );

    unsafe {
        WriteDetour.enable().expect("Should be able to enable write detour.");
        SetOpcodeDetour.call(this, op)
    }
}

fn on_packet_send(packet: *mut c_void) {
    debug!("Packet has been sent.");
    unsafe {
        WriteDetour.disable().expect("Should be able to disable detour.");
        SendPacketDetour.call(packet);
    }
}

fn on_data_written(packet: *mut c_void, content: *const u8, size: usize) {
    debug!("Writing {} bytes.", size);
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
        let target: SetOpcodeFn = mem::transmute(OPCODE_SET_FN);
        SetOpcodeDetour
            .initialize(target, on_packet_create)
            .expect("Should be able to initialize opcode detour");
        SetOpcodeDetour
            .enable()
            .expect("Should be able to enable opcode detour");

        let target: SendPacketFn = mem::transmute(PACKET_SEND_FN);
        SendPacketDetour
            .initialize(target, on_packet_send)
            .expect("Should be able to initialize send detour");
        SendPacketDetour.enable().expect("Should be able to enable send detour");

        let target: WriteDataFn = mem::transmute(PACKET_WRITE_FN);
        WriteDetour
            .initialize(target, on_data_written)
            .expect("Should be able to initialize write detour");

        if should_skip_ad() {
            let target: OpenAdFn = mem::transmute(OPEN_AD_FN);
            OpenAdDetour
                .initialize(target, on_open_ad)
                .expect("Should be able to initialize ad detour");
            OpenAdDetour.enable().expect("Should be able to enable ad detour.");
        }
    }
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
