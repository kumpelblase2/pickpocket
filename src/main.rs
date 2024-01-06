use clap::Parser;
use dll_syringe::process::*;
use dll_syringe::Syringe;
use std::env::set_var;
use std::os::raw::c_void;
use std::os::windows::io::FromRawHandle;
use std::path::{Path, PathBuf};
use windows::core::PCSTR;
use windows::Win32::System::Threading::{
    CreateProcessA, ResumeThread, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOA,
};

// We have to write our custom p/s macros since the once from the windows crate only accept literals.
macro_rules! p {
    ($string: expr) => {{
        let s = std::ffi::CString::new($string).unwrap();
        windows::core::PSTR::from_raw(s.into_raw() as *mut u8)
    }};
}

macro_rules! s {
    ($string: expr) => {{
        let s = std::ffi::CString::new($string).unwrap();
        windows::core::PCSTR::from_raw(s.into_raw() as *mut u8)
    }};
}

fn create_suspended_process(exe_path: &Path, args: &str) -> (OwnedProcess, PROCESS_INFORMATION) {
    let startupinfoa = STARTUPINFOA { ..Default::default() };
    let mut information = PROCESS_INFORMATION { ..Default::default() };
    let parent_dir = exe_path.parent().expect("Should be able to get parent for path");
    let file = exe_path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("sro_client.exe");
    let parent_dir_string = parent_dir
        .as_os_str()
        .to_str()
        .expect("Should be able to resolve parent dir as string.");
    let current_dir = s!(parent_dir_string);

    unsafe {
        CreateProcessA(
            PCSTR::null(),
            p!(format!("{} {}", file, args)),
            None,
            None,
            false,
            CREATE_SUSPENDED,
            None,
            current_dir,
            &startupinfoa,
            &mut information,
        )
        .expect("Process should be created");

        (
            // Unfortunately the handle required here is a winapi HANDLE, while we have a
            // windows-rs HANDLE and thus incompatible.
            OwnedProcess::from_raw_handle(information.hProcess.0 as *mut c_void),
            information,
        )
    }
}

#[derive(Parser)]
struct Cli {
    silkroad: Option<PathBuf>,
    dll: Option<PathBuf>,
    skip_ad: Option<bool>,
}

fn main() {
    let cli_args = Cli::parse();

    set_var("skip_ad", cli_args.skip_ad.unwrap_or(true).to_string());

    let silkroad_path = cli_args
        .silkroad
        .unwrap_or_else(|| PathBuf::from("C:/Program Files (x86)/Silkroad/sro_client.exe"));
    let (process, info) = create_suspended_process(&silkroad_path, "0 /18 0 0 0");

    unsafe {
        let syringe = Syringe::for_process(process);
        if let Err(e) = syringe.inject(
            cli_args
                .dll
                .unwrap_or_else(|| PathBuf::from("C:\\Program Files (x86)\\Silkroad\\pocket.dll")),
        ) {
            eprintln!("{:?}", e);
        }

        ResumeThread(info.hThread);
        ResumeThread(info.hProcess);
    }
}
