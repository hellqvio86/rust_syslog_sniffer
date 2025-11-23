use log::debug;
use pcap::Device;
use std::env;
use syslog_sniffer::parse_syslog_packet;

mod config;

// debug run
// cargo run -- --interface eth0
//
// debug run
// cargo run -- --interface eth0
//
/// Search for a pattern in a file and display the lines that contain it.

#[derive(serde::Serialize)]
struct JsonSummary {
    interval_seconds: u64,
    hosts: std::collections::HashMap<String, HostStats>,
}

#[derive(serde::Serialize)]
struct HostStats {
    count: u64,
    sample: String,
}

fn main() {
    let args = config::Config::parse();

    let mut builder = env_logger::Builder::from_default_env();
    let env_rust_log_is_set = env::var("RUST_LOG").is_ok();
    
    if let Some(level) = config::determine_log_level(args.debug, env_rust_log_is_set) {
        builder.filter_level(level);
    }
    builder.init();

    debug!("Port to sniff: {:?}", args.port);
    debug!("Interface to sniff: {:?}", args.interface);
    debug!("Interval: {} seconds", args.interval);

    let device = Device::list()
        .expect("device lookup failed")
        .into_iter()
        .find(|d| d.name == args.interface)
        .unwrap_or_else(|| panic!("Device {} not found", args.interface));

    let mut cap = pcap::Capture::from_device(device)
        .expect("Failed to create capture")
        .immediate_mode(true)
        .timeout(1000)
        .open()
        .expect("Failed to open capture");

    // Set filter for UDP and the specified port
    let filter = format!("udp port {}", args.port);
    cap.filter(&filter, true).expect("Failed to set filter");

    // Set non-blocking mode to ensure we can exit the loop when interval expires
    cap = match cap.setnonblock() {
        Ok(c) => c,
        Err(e) => panic!("Failed to set non-blocking mode: {:?}", e),
    };

    debug!("Listening on {} for UDP port {}", args.interface, args.port);
    debug!("Datalink: {:?}", cap.get_datalink());
    debug!("Starting capture loop");

    let start_time = std::time::Instant::now();
    let duration = std::time::Duration::from_secs(args.interval);

    // Map: Hostname -> (Count, Sample Message)
    let mut stats: std::collections::HashMap<String, (u64, String)> =
        std::collections::HashMap::new();

    let mut last_report_time = std::time::Instant::now();

    loop {
        // Check if total run interval has expired
        if start_time.elapsed() >= duration {
            break;
        }

        // Periodic reporting logic
        if args.periodic && last_report_time.elapsed().as_secs() >= args.frequency {
            if !stats.is_empty() {
                let mut hosts_map = std::collections::HashMap::new();
                for (hostname, (count, sample)) in &stats {
                    hosts_map.insert(
                        hostname.clone(),
                        HostStats {
                            count: *count,
                            sample: sample.clone(),
                        },
                    );
                }

                let summary = JsonSummary {
                    interval_seconds: args.frequency,
                    hosts: hosts_map,
                };

                println!("{}", serde_json::to_string_pretty(&summary).unwrap());
                stats.clear();
            }
            last_report_time = std::time::Instant::now();
        }

        match cap.next_packet() {
            Ok(packet) => {
                debug!("Received packet: len={}", packet.data.len());

                // Heuristic: Syslog messages typically start with '<' (PRI).
                if let Some(start_index) = packet.data.iter().position(|&b| b == b'<') {
                    if let Some(syslog) = parse_syslog_packet(&packet.data[start_index..]) {
                        let hostname = syslog
                            .hostname
                            .clone()
                            .unwrap_or_else(|| "Unknown".to_string());

                        stats
                            .entry(hostname)
                            .and_modify(|(count, _)| *count += 1)
                            .or_insert((1, syslog.message.clone()));

                        debug!(
                            "Captured from {}: {}",
                            syslog.hostname.as_deref().unwrap_or("Unknown"),
                            syslog.message
                        );
                    }
                } else if let Some(syslog) = parse_syslog_packet(packet.data) {
                    let hostname = syslog
                        .hostname
                        .clone()
                        .unwrap_or_else(|| "Unknown".to_string());
                    stats
                        .entry(hostname)
                        .and_modify(|(count, _)| *count += 1)
                        .or_insert((1, syslog.message.clone()));
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                // Timeout is good, lets us check loop condition
                continue;
            }
            Err(e) => {
                // In non-blocking mode, we might get errors if no packet is ready.
                // Sleep a bit to avoid busy loop
                std::thread::sleep(std::time::Duration::from_millis(10));
                debug!("Error capturing packet (might be empty): {:?}", e);
            }
        }
    }

    // Print final summary if not periodic, or if there are leftover stats in periodic mode
    if !args.periodic || !stats.is_empty() {
        let mut hosts_map = std::collections::HashMap::new();
        for (hostname, (count, sample)) in stats {
            hosts_map.insert(hostname, HostStats { count, sample });
        }

        // For periodic, the last interval might be shorter than frequency
        let interval = if args.periodic {
            last_report_time.elapsed().as_secs()
        } else {
            args.interval
        };

        let summary = JsonSummary {
            interval_seconds: interval,
            hosts: hosts_map,
        };

        println!("{}", serde_json::to_string_pretty(&summary).unwrap());
    }
}
