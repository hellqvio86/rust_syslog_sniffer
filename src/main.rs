#![forbid(unsafe_code)]

use clap::Parser;
use log::{error, warn};
use std::env;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use syslog_sniffer::app::run_sniffer_with_writer;
use syslog_sniffer::capture::{FileCapture, PcapCapture};
use syslog_sniffer::config::{determine_log_level, Config};
use syslog_sniffer::PacketSource;

fn main() -> ExitCode {
    init_and_run(Config::parse())
}

fn init_and_run(args: Config) -> ExitCode {
    let mut builder = env_logger::Builder::from_default_env();
    let env_rust_log_is_set = env::var("RUST_LOG").is_ok();

    if let Some(level) = determine_log_level(args.debug, env_rust_log_is_set) {
        builder.filter_level(level);
    }
    let _ = builder.try_init();

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_signal = shutdown.clone();
    if let Err(e) = ctrlc::set_handler(move || {
        shutdown_signal.store(true, Ordering::SeqCst);
    }) {
        warn!("Could not register signal handler: {}", e);
    }

    run_app(args, shutdown)
}

fn run_app(args: Config, shutdown: Arc<AtomicBool>) -> ExitCode {
    let capture_source: Result<Box<dyn PacketSource>, _> =
        if let Some(ref pcap_file) = args.read_pcap {
            FileCapture::new(pcap_file).map(|c| Box::new(c) as Box<dyn PacketSource>)
        } else {
            let iface = args.interface.as_deref().unwrap_or("lo");
            PcapCapture::new(
                iface,
                args.port,
                args.promisc,
                args.snaplen,
                args.buffer_size,
            )
            .map(|c| Box::new(c) as Box<dyn PacketSource>)
        };

    match capture_source {
        Ok(cap) => {
            let stdout = std::io::stdout();
            match run_sniffer_with_writer(args, cap, stdout.lock(), shutdown) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    error!("Sniffer failed: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
        Err(e) => {
            error!("Failed to setup capture: {}", e);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_run_app_invalid_device() {
        let config = Config::parse_from(vec![
            "syslog_sniffer",
            "--interface",
            "non_existent_device_xyz",
            "--port",
            "514",
        ]);
        let shutdown = Arc::new(AtomicBool::new(false));
        assert_eq!(run_app(config.clone(), shutdown), ExitCode::FAILURE);
        assert_eq!(init_and_run(config), ExitCode::FAILURE);
    }

    #[test]
    fn test_run_app_invalid_pcap() {
        let config = Config::parse_from(vec![
            "syslog_sniffer",
            "--read-pcap",
            "/non/existent/file.pcap",
        ]);
        let shutdown = Arc::new(AtomicBool::new(false));
        assert_eq!(run_app(config, shutdown), ExitCode::FAILURE);
    }

    #[test]
    fn test_run_app_valid_pcap() {
        let dummy_pkt = vec![0x00; 14];
        let mut file_bytes = Vec::new();
        // Global Header (24 bytes)
        file_bytes.extend_from_slice(&0xa1b2c3d4u32.to_ne_bytes());
        file_bytes.extend_from_slice(&2u16.to_ne_bytes());
        file_bytes.extend_from_slice(&4u16.to_ne_bytes());
        file_bytes.extend_from_slice(&0i32.to_ne_bytes());
        file_bytes.extend_from_slice(&0u32.to_ne_bytes());
        file_bytes.extend_from_slice(&65535u32.to_ne_bytes());
        file_bytes.extend_from_slice(&1u32.to_ne_bytes());

        // Packet Header (16 bytes)
        file_bytes.extend_from_slice(&1700000000u32.to_ne_bytes());
        file_bytes.extend_from_slice(&0u32.to_ne_bytes());
        let len = dummy_pkt.len() as u32;
        file_bytes.extend_from_slice(&len.to_ne_bytes());
        file_bytes.extend_from_slice(&len.to_ne_bytes());
        file_bytes.extend_from_slice(&dummy_pkt);

        let path = std::env::temp_dir().join(format!("test_main_pcap_{}.pcap", std::process::id()));
        std::fs::write(&path, file_bytes).expect("write temp pcap");

        let config = Config::parse_from(vec![
            "syslog_sniffer",
            "--read-pcap",
            path.to_str().unwrap(),
        ]);
        let shutdown = Arc::new(AtomicBool::new(false));
        assert_eq!(run_app(config, shutdown), ExitCode::SUCCESS);

        // Validation failure during run_sniffer_with_writer
        let invalid_config = Config::parse_from(vec![
            "syslog_sniffer",
            "--read-pcap",
            path.to_str().unwrap(),
            "--periodic",
            "--duration",
            "5",
            "--frequency",
            "10",
        ]);
        let shutdown2 = Arc::new(AtomicBool::new(false));
        assert_eq!(run_app(invalid_config, shutdown2), ExitCode::FAILURE);

        let _ = std::fs::remove_file(&path);
    }
}
