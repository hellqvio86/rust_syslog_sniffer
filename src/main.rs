use log::debug;
use std::env;
use syslog_sniffer::capture::setup_capture;
use syslog_sniffer::config::{determine_log_level, Config};
use syslog_sniffer::parse_syslog_packet;
use syslog_sniffer::stats::StatsTracker;

fn main() {
    let args = Config::parse();

    let mut builder = env_logger::Builder::from_default_env();
    let env_rust_log_is_set = env::var("RUST_LOG").is_ok();

    if let Some(level) = determine_log_level(args.debug, env_rust_log_is_set) {
        builder.filter_level(level);
    }
    builder.init();

    debug!("Port to sniff: {:?}", args.port);
    debug!("Interface to sniff: {:?}", args.interface);
    debug!("Interval: {} seconds", args.interval);

    let mut cap = setup_capture(&args.interface, args.port);

    debug!("Listening on {} for UDP port {}", args.interface, args.port);
    debug!("Datalink: {:?}", cap.get_datalink());
    debug!("Starting capture loop");

    let start_time = std::time::Instant::now();
    let duration = std::time::Duration::from_secs(args.interval);

    let mut stats = StatsTracker::new();
    let mut last_report_time = std::time::Instant::now();

    loop {
        if start_time.elapsed() >= duration {
            break;
        }

        if args.periodic && last_report_time.elapsed().as_secs() >= args.frequency {
            if !stats.is_empty() {
                let summary = stats.get_summary(args.frequency);
                println!("{}", serde_json::to_string_pretty(&summary).unwrap());
                stats.clear();
            }
            last_report_time = std::time::Instant::now();
        }

        match cap.next_packet() {
            Ok(packet) => {
                debug!("Received packet: len={}", packet.data.len());

                // Heuristic: Syslog messages typically start with '<' (PRI).
                // We try to find the start of the syslog message.
                let syslog_msg =
                    if let Some(start_index) = packet.data.iter().position(|&b| b == b'<') {
                        parse_syslog_packet(&packet.data[start_index..])
                    } else {
                        parse_syslog_packet(packet.data)
                    };

                if let Some(syslog) = syslog_msg {
                    let hostname = syslog
                        .hostname
                        .clone()
                        .unwrap_or_else(|| "Unknown".to_string());
                    stats.add_entry(hostname.clone(), syslog.message.clone());
                    debug!(
                        "Captured from {}: {}",
                        syslog.hostname.as_deref().unwrap_or("Unknown"),
                        syslog.message
                    );
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                continue;
            }
            Err(e) => {
                std::thread::sleep(std::time::Duration::from_millis(10));
                debug!("Error capturing packet (might be empty): {:?}", e);
            }
        }
    }

    if !args.periodic || !stats.is_empty() {
        let interval = if args.periodic {
            last_report_time.elapsed().as_secs()
        } else {
            args.interval
        };
        let summary = stats.get_summary(interval);
        println!("{}", serde_json::to_string_pretty(&summary).unwrap());
    }
}
