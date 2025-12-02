use crate::config::Config;
use crate::stats::StatsTracker;
use crate::{parse_syslog_packet, PacketSource};
use log::debug;
use std::time::{Duration, Instant};

pub fn run_sniffer<S: PacketSource>(config: Config, mut source: S) {
    debug!("Port to sniff: {:?}", config.port);
    debug!("Interface to sniff: {:?}", config.interface);
    debug!("Interval: {} seconds", config.interval);

    debug!("Datalink: {}", source.get_datalink());
    debug!("Starting capture loop");

    let start_time = Instant::now();
    let duration = Duration::from_secs(config.interval);

    let mut stats = StatsTracker::new();
    let mut last_report_time = Instant::now();

    loop {
        if start_time.elapsed() >= duration {
            break;
        }

        if config.periodic && last_report_time.elapsed().as_secs() >= config.frequency {
            if !stats.is_empty() {
                let summary = stats.get_summary(config.frequency);
                println!("{}", serde_json::to_string_pretty(&summary).unwrap());
                stats.clear();
            }
            last_report_time = Instant::now();
        }

        match source.next_packet() {
            Ok(Some(packet)) => {
                debug!("Received packet: len={}", packet.data.len());

                // Heuristic: Syslog messages typically start with '<' (PRI).
                // We try to find the start of the syslog message.
                let syslog_msg =
                    if let Some(start_index) = packet.data.iter().position(|&b| b == b'<') {
                        parse_syslog_packet(&packet.data[start_index..])
                    } else {
                        parse_syslog_packet(&packet.data)
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
            Ok(None) => {
                // Timeout
                continue;
            }
            Err(e) => {
                std::thread::sleep(Duration::from_millis(10));
                debug!("Error capturing packet: {}", e);
            }
        }
    }

    if !config.periodic || !stats.is_empty() {
        let interval = if config.periodic {
            last_report_time.elapsed().as_secs()
        } else {
            config.interval
        };
        let summary = stats.get_summary(interval);
        println!("{}", serde_json::to_string_pretty(&summary).unwrap());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PacketData;
    use std::collections::VecDeque;

    struct MockPacketSource {
        packets: VecDeque<Result<Option<PacketData>, String>>,
    }

    impl MockPacketSource {
        fn new(packets: Vec<Result<Option<PacketData>, String>>) -> Self {
            Self {
                packets: packets.into(),
            }
        }
    }

    impl PacketSource for MockPacketSource {
        fn next_packet(&mut self) -> Result<Option<PacketData>, String> {
            self.packets.pop_front().unwrap_or(Ok(None))
        }

        fn get_datalink(&self) -> String {
            "MOCK".to_string()
        }
    }

    fn init_logger() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_run_sniffer_basic() {
        init_logger();
        let config = Config {
            interface: "lo".to_string(),
            port: 514,
            interval: 1,
            debug: false,
            periodic: false,
            frequency: 0,
        };

        let packet_data = "<13>Oct 11 22:14:15 mymachine su: su root".as_bytes().to_vec();
        let packets = vec![
            Ok(Some(PacketData { data: packet_data })),
            Ok(None), // Simulate timeout
        ];

        let source = MockPacketSource::new(packets);
        run_sniffer(config, source);
        // We can capture stdout to verify output, or just ensure it doesn't panic
    }

    #[test]
    fn test_run_sniffer_periodic() {
        let config = Config {
            interface: "lo".to_string(),
            port: 514,
            interval: 1, // Run for 1 second
            debug: true,
            periodic: true,
            frequency: 0, // Report every iteration (effectively)
        };

        let packet_data = "<13>Oct 11 22:14:15 mymachine su: su root".as_bytes().to_vec();
        // Send enough packets to trigger logic
        let packets = vec![
            Ok(Some(PacketData { data: packet_data.clone() })),
            Ok(Some(PacketData { data: packet_data })),
            Ok(None),
        ];

        let source = MockPacketSource::new(packets);
        run_sniffer(config, source);
    }

    #[test]
    fn test_run_sniffer_invalid_packet() {
        let config = Config {
            interface: "lo".to_string(),
            port: 514,
            interval: 1,
            debug: false,
            periodic: false,
            frequency: 5,
        };

        let packets = vec![
            Ok(Some(PacketData { data: vec![0, 1, 2, 3] })), // Invalid syslog
            Ok(Some(PacketData { data: vec![] })), // Empty
            Ok(None),
        ];

        let source = MockPacketSource::new(packets);
        run_sniffer(config, source);
    }

    #[test]
    fn test_run_sniffer_error_packet() {
        let config = Config {
            interface: "lo".to_string(),
            port: 514,
            interval: 1,
            debug: false,
            periodic: false,
            frequency: 5,
        };

        let packets = vec![
            Err("Simulated error".to_string()),
            Ok(None),
        ];

        let source = MockPacketSource::new(packets);
        run_sniffer(config, source);
    }
    #[test]
    fn test_run_sniffer_no_hostname_packet() {
        let config = Config {
            interface: "lo".to_string(),
            port: 514,
            interval: 1,
            debug: true,
            periodic: false,
            frequency: 5,
        };

        let packet_data = "Simple message without hostname".as_bytes().to_vec();
        let packets = vec![
            Ok(Some(PacketData { data: packet_data })),
            Ok(None),
        ];

        let source = MockPacketSource::new(packets);
        run_sniffer(config, source);
    }
}
