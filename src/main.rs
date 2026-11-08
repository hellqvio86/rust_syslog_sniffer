#![forbid(unsafe_code)]

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
    let args = Config::parse();

    let mut builder = env_logger::Builder::from_default_env();
    let env_rust_log_is_set = env::var("RUST_LOG").is_ok();

    if let Some(level) = determine_log_level(args.debug, env_rust_log_is_set) {
        builder.filter_level(level);
    }
    builder.init();

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_signal = shutdown.clone();
    if let Err(e) = ctrlc::set_handler(move || {
        shutdown_signal.store(true, Ordering::SeqCst);
    }) {
        warn!("Could not register signal handler: {}", e);
    }

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
