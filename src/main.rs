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
    let args = match Config::try_parse() {
        Ok(c) => c,
        Err(e) => e.exit(),
    };
    init_and_run(args)
}

fn init_and_run(args: Config) -> ExitCode {
    if let Err(e) = args.validate() {
        eprintln!("error: {}", e);
        return ExitCode::from(2);
    }

    let mut builder = env_logger::Builder::from_default_env();
    let env_rust_log_is_set = env::var("RUST_LOG").is_ok();

    if let Some(level) = determine_log_level(args.debug, env_rust_log_is_set) {
        builder.filter_level(level);
    }
    let _ = builder.try_init();

    if args.interval.is_some() {
        warn!("The --interval argument is deprecated; use --duration instead.");
    }

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
            FileCapture::new(pcap_file, args.port).map(|c| Box::new(c) as Box<dyn PacketSource>)
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
            let options = syslog_sniffer::RunOptions::from(&args);
            match run_sniffer_with_writer(options, cap, stdout.lock(), shutdown) {
                Ok(()) | Err(syslog_sniffer::error::SnifferError::OutputClosed) => {
                    ExitCode::SUCCESS
                }
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
        let dummy_pkt = syslog_sniffer::capture::test_helpers::craft_ethernet_ipv4_udp(
            514,
            b"<13>Oct 11 22:14:15 myhost test",
        );
        let path = std::env::temp_dir().join(format!("test_main_pcap_{}.pcap", std::process::id()));
        syslog_sniffer::capture::test_helpers::write_test_pcap(&path, 1, &[&dummy_pkt]);

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
        assert_eq!(
            run_app(invalid_config.clone(), shutdown2),
            ExitCode::FAILURE
        );
        assert_eq!(init_and_run(invalid_config), ExitCode::from(2));

        let _ = std::fs::remove_file(&path);
    }
}
