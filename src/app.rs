use crate::config::{Config, OutputFormat};
use crate::decode::decode_datagram;
use crate::error::SnifferError;
use crate::stats::{truncate_utf8, StatsTracker};
use crate::{parse_syslog_packet, PacketSource};
use log::{debug, error, warn};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

const MAX_CONSECUTIVE_ERRORS: usize = 50;

pub fn run_sniffer<S: PacketSource>(config: Config, source: S) -> Result<(), SnifferError> {
    let stdout = std::io::stdout();
    let shutdown = Arc::new(AtomicBool::new(false));
    run_sniffer_with_writer(config, source, stdout.lock(), shutdown)
}

pub fn run_sniffer_with_writer<S: PacketSource, W: Write>(
    config: Config,
    mut source: S,
    mut writer: W,
    shutdown: Arc<AtomicBool>,
) -> Result<(), SnifferError> {
    if std::env::args().any(|a| a == "--interval" || a.starts_with("--interval=")) {
        warn!("The --interval argument is deprecated; use --duration instead.");
    }

    config
        .validate()
        .map_err(|e| SnifferError::Capture(format!("Configuration error: {}", e)))?;

    debug!("Port to sniff: {:?}", config.port);
    debug!("Interface to sniff: {:?}", config.interface);
    debug!(
        "Duration: {:?} seconds (periodic={})",
        config.effective_duration_secs(),
        config.periodic
    );
    debug!("Datalink: {:?}", source.datalink());
    debug!("Starting capture loop");

    let total_duration = config.effective_duration_secs().map(Duration::from_secs);
    let sample_bytes = config.effective_sample_bytes();
    let mut stats = StatsTracker::new(config.max_hosts, sample_bytes, config.key_by);

    let start_instant = Instant::now();
    let mut window_start_instant = Instant::now();
    let mut window_start_time = SystemTime::now();

    let freq_dur = Duration::from_secs(config.frequency.max(1));
    let mut next_report_instant = Instant::now() + freq_dur;

    let mut consecutive_errors: usize = 0;
    let mut last_error_log = Instant::now() - Duration::from_secs(2);

    loop {
        if shutdown.load(Ordering::Relaxed) {
            debug!("Shutdown signal received, exiting capture loop");
            break;
        }

        if let Some(dur) = total_duration {
            if start_instant.elapsed() >= dur {
                break;
            }
        }

        if config.periodic && Instant::now() >= next_report_instant {
            let window_end_time = SystemTime::now();
            let window_duration_secs = window_start_instant.elapsed().as_secs_f64();

            if config.emit_empty || !stats.is_empty() {
                stats.set_capture_stats(source.stats());
                let summary = stats.get_summary(
                    config.frequency,
                    window_duration_secs,
                    window_start_time,
                    window_end_time,
                );

                let json = match config.format {
                    OutputFormat::Pretty => serde_json::to_string_pretty(&summary),
                    OutputFormat::Ndjson => serde_json::to_string(&summary),
                }
                .map_err(|e| SnifferError::Capture(format!("JSON serialization failed: {}", e)))?;

                if let Err(e) = writeln!(writer, "{}", json) {
                    if e.kind() == std::io::ErrorKind::BrokenPipe {
                        return Ok(());
                    }
                    return Err(SnifferError::Capture(format!(
                        "Failed to write output: {}",
                        e
                    )));
                }
                stats.clear();
            }

            window_start_instant = Instant::now();
            window_start_time = SystemTime::now();
            while next_report_instant <= Instant::now() {
                next_report_instant += freq_dur;
            }
        }

        match source.next_packet() {
            Ok(Some(packet)) => {
                consecutive_errors = 0;
                stats.record_packet_seen();
                debug!("Received packet: len={}", packet.data.len());

                if let Some(datagram) = decode_datagram(source.datalink(), &packet.data) {
                    stats.record_datagram_decoded();
                    if let Some(syslog) = parse_syslog_packet(datagram.payload) {
                        stats.add_entry(
                            syslog.hostname.as_deref(),
                            datagram.src_ip,
                            &syslog.message,
                            syslog.is_non_utf8,
                        );
                        debug!(
                            "Captured from {:?} (src_ip={}): {}",
                            syslog.hostname,
                            datagram.src_ip,
                            truncate_utf8(&syslog.message, sample_bytes.max(64))
                        );
                    }
                } else {
                    stats.record_decode_error();
                }
            }
            Ok(None) => {
                consecutive_errors = 0;
                // Idle / read timeout: sleep briefly to avoid busy-loop
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(SnifferError::CaptureClosed(_)) => {
                debug!("Packet stream closed/exhausted, finishing capture loop");
                break;
            }
            Err(e) => {
                consecutive_errors += 1;
                if last_error_log.elapsed() >= Duration::from_secs(1) {
                    warn!("Capture error (consecutive={}): {}", consecutive_errors, e);
                    last_error_log = Instant::now();
                }
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                    error!(
                        "Exceeded maximum consecutive capture errors ({}): {}",
                        MAX_CONSECUTIVE_ERRORS, e
                    );
                    return Err(SnifferError::PersistentCapture(format!(
                        "Exceeded {} consecutive capture errors: {}",
                        MAX_CONSECUTIVE_ERRORS, e
                    )));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    if config.emit_empty || !stats.is_empty() {
        let window_end_time = SystemTime::now();
        let window_duration_secs = window_start_instant.elapsed().as_secs_f64();
        let interval_seconds = if config.periodic {
            window_duration_secs.round() as u64
        } else {
            config
                .effective_duration_secs()
                .unwrap_or(window_duration_secs.round() as u64)
        };

        stats.set_capture_stats(source.stats());
        let summary = stats.get_summary(
            interval_seconds,
            window_duration_secs,
            window_start_time,
            window_end_time,
        );

        let json = match config.format {
            OutputFormat::Pretty => serde_json::to_string_pretty(&summary),
            OutputFormat::Ndjson => serde_json::to_string(&summary),
        }
        .map_err(|e| SnifferError::Capture(format!("JSON serialization failed: {}", e)))?;

        if let Err(e) = writeln!(writer, "{}", json) {
            if e.kind() == std::io::ErrorKind::BrokenPipe {
                return Ok(());
            }
            return Err(SnifferError::Capture(format!(
                "Failed to write output: {}",
                e
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::KeyBy;
    use crate::decode::Datalink;
    use crate::error::SnifferError;
    use crate::stats::JsonSummary;
    use crate::PacketData;
    use std::collections::VecDeque;
    use std::io::Cursor;

    fn create_test_frame(payload: &[u8]) -> Vec<u8> {
        let mut eth = Vec::new();
        eth.extend_from_slice(&[0x00; 12]);
        eth.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4

        let ip_total_len = (20 + 8 + payload.len()) as u16;
        eth.push(0x45);
        eth.push(0x00);
        eth.extend_from_slice(&ip_total_len.to_be_bytes());
        eth.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        eth.push(64);
        eth.push(17); // UDP
        eth.extend_from_slice(&[0x00, 0x00]);
        eth.extend_from_slice(&[10, 0, 0, 1]); // src IP
        eth.extend_from_slice(&[10, 0, 0, 2]); // dst IP

        let udp_len = (8 + payload.len()) as u16;
        eth.extend_from_slice(&12345u16.to_be_bytes());
        eth.extend_from_slice(&514u16.to_be_bytes());
        eth.extend_from_slice(&udp_len.to_be_bytes());
        eth.extend_from_slice(&[0x00, 0x00]);
        eth.extend_from_slice(payload);
        eth
    }

    fn default_test_config() -> Config {
        Config {
            interface: Some("lo".to_string()),
            port: 514,
            duration: Some(1),
            debug: false,
            periodic: false,
            frequency: 1,
            max_hosts: 10_000,
            sample_bytes: 256,
            no_sample: false,
            format: OutputFormat::Pretty,
            emit_empty: false,
            key_by: KeyBy::Hostname,
            promisc: false,
            buffer_size: 2097152,
            snaplen: 65535,
            read_pcap: None,
        }
    }

    struct MockPacketSource {
        packets: VecDeque<Result<Option<PacketData>, SnifferError>>,
        datalink: Datalink,
    }

    impl MockPacketSource {
        fn new(packets: Vec<Result<Option<PacketData>, SnifferError>>) -> Self {
            Self {
                packets: packets.into(),
                datalink: Datalink::Ethernet,
            }
        }
    }

    impl PacketSource for MockPacketSource {
        fn next_packet(&mut self) -> Result<Option<PacketData>, SnifferError> {
            self.packets
                .pop_front()
                .unwrap_or(Err(SnifferError::CaptureClosed("exhausted".to_string())))
        }

        fn datalink(&self) -> Datalink {
            self.datalink
        }
    }

    fn init_logger() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_run_sniffer_basic() {
        init_logger();
        let config = default_test_config();

        let packet_data = create_test_frame(b"<13>Oct 11 22:14:15 mymachine su: su root");
        let packets = vec![Ok(Some(PacketData { data: packet_data })), Ok(None)];

        let source = MockPacketSource::new(packets);
        let mut buf = Cursor::new(Vec::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        let res = run_sniffer_with_writer(config, source, &mut buf, shutdown);
        assert!(res.is_ok());

        let output = String::from_utf8(buf.into_inner()).unwrap();
        let summary: JsonSummary = serde_json::from_str(&output).expect("valid json summary");
        assert_eq!(summary.schema_version, 1);
        assert_eq!(summary.interval_seconds, 1);
        assert_eq!(summary.packets_seen, 1);
        assert_eq!(summary.datagrams_decoded, 1);
        assert_eq!(summary.hosts.len(), 1);
        assert!(summary.hosts.contains_key("mymachine"));
        assert_eq!(summary.hosts["mymachine"].count, 1);
        assert_eq!(summary.hosts["mymachine"].sources, vec!["10.0.0.1"]);
    }

    #[test]
    fn test_run_sniffer_ndjson_format() {
        let mut config = default_test_config();
        config.format = OutputFormat::Ndjson;

        let packet_data = create_test_frame(b"<13>Oct 11 22:14:15 mymachine su: su root");
        let packets = vec![Ok(Some(PacketData { data: packet_data })), Ok(None)];

        let source = MockPacketSource::new(packets);
        let mut buf = Cursor::new(Vec::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        let res = run_sniffer_with_writer(config, source, &mut buf, shutdown);
        assert!(res.is_ok());

        let output = String::from_utf8(buf.into_inner()).unwrap();
        assert_eq!(output.lines().count(), 1);
        assert!(output.starts_with("{\"schema_version\":1,"));
    }

    #[test]
    fn test_run_sniffer_periodic() {
        let mut config = default_test_config();
        config.debug = true;
        config.periodic = true;
        config.frequency = 1;

        let packet_data = create_test_frame(b"<13>Oct 11 22:14:15 mymachine su: su root");
        let packets = vec![
            Ok(Some(PacketData {
                data: packet_data.clone(),
            })),
            Ok(Some(PacketData { data: packet_data })),
            Ok(None),
        ];

        let source = MockPacketSource::new(packets);
        let mut buf = Cursor::new(Vec::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        let res = run_sniffer_with_writer(config, source, &mut buf, shutdown);
        assert!(res.is_ok());

        let output = String::from_utf8(buf.into_inner()).unwrap();
        assert!(output.contains("\"mymachine\""));
    }

    #[test]
    fn test_run_sniffer_invalid_packet() {
        let config = default_test_config();

        let packets = vec![
            Ok(Some(PacketData {
                data: vec![0, 1, 2, 3],
            })), // Invalid frame
            Ok(Some(PacketData { data: vec![] })), // Empty
            Ok(None),
        ];

        let source = MockPacketSource::new(packets);
        let mut buf = Cursor::new(Vec::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        let res = run_sniffer_with_writer(config, source, &mut buf, shutdown);
        assert!(res.is_ok());

        let output = String::from_utf8(buf.into_inner()).unwrap();
        let summary: JsonSummary = serde_json::from_str(&output).expect("valid json");
        assert_eq!(summary.packets_seen, 2);
        assert_eq!(summary.decode_errors, 2);
    }

    #[test]
    fn test_run_sniffer_persistent_error() {
        let mut config = default_test_config();
        config.duration = Some(10);
        config.frequency = 5;

        let packets: Vec<Result<Option<PacketData>, SnifferError>> = (0..50)
            .map(|_| Err(SnifferError::Capture("Simulated IO error".to_string())))
            .collect();

        let source = MockPacketSource::new(packets);
        let mut buf = Cursor::new(Vec::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        let res = run_sniffer_with_writer(config, source, &mut buf, shutdown);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("consecutive capture errors"));
    }

    #[test]
    fn test_run_sniffer_shutdown_signal() {
        let mut config = default_test_config();
        config.duration = Some(1000);

        let shutdown = Arc::new(AtomicBool::new(true)); // Already signalled
        let source = MockPacketSource::new(vec![]);
        let mut buf = Cursor::new(Vec::new());

        let res = run_sniffer_with_writer(config, source, &mut buf, shutdown);
        assert!(res.is_ok());
    }
}
