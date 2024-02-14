use crate::data::{ClientMessage, Direction};
use clap::{ArgAction, Parser};
use dll_syringe::process::*;
use dll_syringe::Syringe;
use ipc_channel::ipc::{IpcOneShotServer, TryRecvError};
use log::{error, info};
use std::env::set_var;
use std::fs::{File, OpenOptions};
use std::io::{stdout, Write};
use std::ops::Not;
use std::os::raw::c_void;
use std::os::windows::io::FromRawHandle;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;
use windows::core::PCSTR;
use windows::Win32::System::Threading::{
    CreateProcessA, ResumeThread, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOA,
};

mod data;

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
    let startupinfoa = STARTUPINFOA::default();
    let mut information = PROCESS_INFORMATION::default();
    let parent_dir = exe_path
        .parent()
        .expect("Should be able to get parent for path");
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
    #[clap(
        long,
        help = "Specify the location of the `sro_client.exe` executable. By default, this will fall back to the default Silkroad Online installation directory, C:/Program Files (x86)/Silkroad/sro_client.exe ."
    )]
    silkroad: Option<PathBuf>,
    #[clap(
        long,
        help = "Specify the location of the `pocket.dll` library. By default, this will expect the dll to be placed inside the default installation directory of Silkroad Online."
    )]
    dll: Option<PathBuf>,
    #[clap(
    long,
    help = "Do not skip the advertisement after the client closes.",
    action = ArgAction::SetFalse,
    default_missing_value("true"),
    default_value("true"),
    )]
    no_skip_ad: bool,
    #[clap(
        long,
        help = "Specify the address for the packet send function. Currently unused."
    )]
    send_address: Option<usize>,
    #[clap(long, help = "Specify the address for the data write function.")]
    write_address: Option<usize>,
    #[clap(
        long,
        help = "Specify the address for the packet enqueuing function, which is run to setup a packet as well as sending one."
    )]
    opcode_address: Option<usize>,
    #[clap(long, help = "Specify the address for the data reading function.")]
    read_address: Option<usize>,
    #[clap(
        long,
        help = "Specify the address for the packet accepting/handling function."
    )]
    accept_address: Option<usize>,
    #[clap(
        long,
        help = "Specify the address for the function opening the advertisement window."
    )]
    skip_ad_address: Option<usize>,
    #[clap(long, short, help = "Specify the output file for the log and packets.")]
    output_file: Option<PathBuf>,
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
                    data.iter()
                        .map(|b| format!("{:x}", b))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
                .as_bytes(),
            )?;
        }
        self.file.write(b"\n")?;
        self.file.flush()?;
        Ok(())
    }

    fn close(mut self) {
        self.finish_current_writing_packet();
        self.finish_current_read_packet();
    }
}

fn handle_message(message: ClientMessage, receiver: &mut PacketRecorder) {
    match message {
        ClientMessage::Log(data) => {
            stdout().write(&data).unwrap();
        }
        ClientMessage::PacketStart(opcode, direction) => match direction {
            Direction::ToServer => receiver.start_writing_packet(opcode),
            Direction::ToClient => receiver.start_reading_packet(opcode),
        },
        ClientMessage::PacketData(direction, data) => match direction {
            Direction::ToServer => receiver.record_written_data(data),
            Direction::ToClient => receiver.record_read_data(data),
        },
        ClientMessage::PacketFinish(direction) => match direction {
            Direction::ToServer => receiver.finish_current_writing_packet(),
            Direction::ToClient => receiver.finish_current_read_packet(),
        },
    }
}

const SRO_CLIENT_PATH: &str = "C:/Program Files (x86)/Silkroad/sro_client.exe";
const DEFAULT_DLL_PATH: &str = "C:/Program Files (x86)/Silkroad/pocket.dll";

fn main() {
    let cli_args = Cli::parse();

    let (server, server_name) =
        IpcOneShotServer::<ClientMessage>::new().expect("Should be able to setup server.");

    set_var("SKIP_AD", cli_args.no_skip_ad.not().to_string());

    if let Some(send_address) = cli_args.send_address {
        set_var("PACKET_SEND_ADDRESS", send_address.to_string());
    }

    if let Some(write_address) = cli_args.write_address {
        set_var("PACKET_WRITE_ADDRESS", write_address.to_string());
    }

    if let Some(opcode_address) = cli_args.opcode_address {
        set_var("PACKET_OPCODE_ADDRESS", opcode_address.to_string());
    }

    if let Some(read_address) = cli_args.read_address {
        set_var("PACKET_READ_ADDRESS", read_address.to_string());
    }

    if let Some(accept_address) = cli_args.accept_address {
        set_var("PACKET_ACCEPT_ADDRESS", accept_address.to_string());
    }

    if let Some(skip_address) = cli_args.skip_ad_address {
        set_var("AD_OPEN_ADDRESS", skip_address.to_string());
    }

    set_var("IPC_SERVER", server_name);

    let silkroad_path = cli_args
        .silkroad
        .unwrap_or_else(|| PathBuf::from(SRO_CLIENT_PATH));
    let (process, info) = create_suspended_process(&silkroad_path, "0 /18 0 0 0");

    unsafe {
        let syringe = Syringe::for_process(process);
        if let Err(e) = syringe.inject(
            cli_args
                .dll
                .unwrap_or_else(|| PathBuf::from(DEFAULT_DLL_PATH)),
        ) {
            eprintln!("{:?}", e);
        }

        ResumeThread(info.hThread);
        ResumeThread(info.hProcess);
    }

    let target_path = cli_args.output_file.unwrap_or(PathBuf::from("packets.txt"));

    let f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(target_path)
        .expect("Should be able to open file");

    let mut recorder = PacketRecorder {
        file: f,
        current_write_packet: None,
        current_read_packet: None,
    };

    let (recv, data) = server.accept().expect("Should be able to accept sender");
    handle_message(data, &mut recorder);
    loop {
        match recv.try_recv() {
            Ok(message) => handle_message(message, &mut recorder),
            Err(TryRecvError::Empty) => sleep(Duration::from_millis(10)),
            Err(e) => {
                error!("Encountered error while receiving: {:?}", e);
                break;
            }
        }
    }

    recorder.close();
    info!("Done");
}
