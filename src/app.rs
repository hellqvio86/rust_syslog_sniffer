use crate::config::{OutputFormat, RunOptions};
use crate::decode::{decode_datagram, DecodeError};
use crate::error::SnifferError;
use crate::stats::{truncate_utf8, StatsTracker};
use crate::{parse_syslog_packet, PacketSource};
use log::{debug, error, warn};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

const MAX_CONSECUTIVE_ERRORS: usize = 50;

pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
    fn sleep(&self, duration: Duration);
    fn system_now(&self) -> SystemTime;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct RealClock;

impl Clock for RealClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
    fn system_now(&self) -> SystemTime {
        SystemTime::now()
    }
}

pub fn run_sniffer<S: PacketSource>(options: RunOptions, source: S) -> Result<(), SnifferError> {
    let stdout = std::io::stdout();
    let shutdown = Arc::new(AtomicBool::new(false));
    run_sniffer_with_writer_and_clock(options, source, stdout.lock(), shutdown, RealClock)
}

pub fn run_sniffer_with_writer<S: PacketSource, W: Write>(
    options: RunOptions,
    source: S,
    writer: W,
    shutdown: Arc<AtomicBool>,
) -> Result<(), SnifferError> {
    run_sniffer_with_writer_and_clock(options, source, writer, shutdown, RealClock)
}

pub fn run_sniffer_with_writer_and_clock<S: PacketSource, W: Write, C: Clock>(
    options: RunOptions,
    mut source: S,
    mut writer: W,
    shutdown: Arc<AtomicBool>,
    clock: C,
) -> Result<(), SnifferError> {
    options.validate().map_err(SnifferError::Config)?;

    debug!("Port to sniff: {:?}", options.port);
    debug!(
        "Duration: {:?} seconds (periodic={})",
        options.duration, options.periodic
    );
    debug!("Datalink: {:?}", source.datalink());
    debug!("Starting capture loop");

    let total_duration = options.duration.map(Duration::from_secs);
    let sample_bytes = options.sample_bytes;
    let mut stats = StatsTracker::new(
        options.max_hosts,
        options.max_sources,
        sample_bytes,
        options.key_by,
    );

    let start_instant = clock.now();
    let mut window_start_instant = clock.now();
    let mut window_start_time = clock.system_now();

    let freq_dur = Duration::from_secs(options.frequency.max(1));
    let mut next_report_instant = start_instant + freq_dur;

    let mut consecutive_errors: usize = 0;
    let mut last_error_log = clock.now() - Duration::from_secs(2);
    let datalink = source.datalink();

    loop {
        if shutdown.load(Ordering::Relaxed) {
            debug!("Shutdown signal received, exiting capture loop");
            break;
        }

        if let Some(dur) = total_duration {
            if clock.now().duration_since(start_instant) >= dur {
                break;
            }
        }

        if options.periodic && clock.now() >= next_report_instant {
            let window_end_time = clock.system_now();
            let window_duration_secs = clock
                .now()
                .duration_since(window_start_instant)
                .as_secs_f64();

            if options.emit_empty || !stats.is_empty() {
                stats.set_capture_stats(source.stats());
                let summary = stats.get_summary(
                    options.frequency,
                    window_duration_secs,
                    window_start_time,
                    window_end_time,
                );

                let json = match options.format {
                    OutputFormat::Pretty => serde_json::to_string_pretty(&summary),
                    OutputFormat::Ndjson => serde_json::to_string(&summary),
                }
                .map_err(|e| SnifferError::Capture(format!("JSON serialization failed: {}", e)))?;

                write_summary_json(&mut writer, &json)?;
                stats.clear();
            }

            let scheduled_deadline = next_report_instant;
            while next_report_instant <= clock.now() {
                next_report_instant += freq_dur;
            }
            window_start_instant = scheduled_deadline;
            window_start_time = window_end_time;
        }

        match source.next_packet() {
            Ok(Some(packet)) => {
                consecutive_errors = 0;
                stats.record_packet_seen();
                debug!("Received packet: len={}", packet.data.len());

                let decoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    decode_datagram(datalink, &packet.data)
                }));
                let decode_res = match decoded {
                    Ok(res) => res,
                    Err(_) => {
                        stats.record_decode_error();
                        continue;
                    }
                };

                match decode_res {
                    Ok(datagram) => {
                        if datagram.dst_port != options.port {
                            stats.record_non_matching_port();
                            continue;
                        }
                        stats.record_datagram_decoded();
                        let parsed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            parse_syslog_packet(datagram.payload)
                        }));
                        match parsed {
                            Ok(Some(syslog)) => {
                                stats.add_entry(
                                    syslog.hostname.as_deref(),
                                    datagram.src_ip,
                                    &syslog.message,
                                    syslog.is_non_utf8,
                                );
                                if sample_bytes > 0 {
                                    debug!(
                                        "Captured from {:?} (src_ip={}): {}",
                                        syslog.hostname,
                                        datagram.src_ip,
                                        truncate_utf8(&syslog.message, sample_bytes)
                                    );
                                } else {
                                    debug!(
                                        "Captured from {:?} (src_ip={}): len={}",
                                        syslog.hostname,
                                        datagram.src_ip,
                                        syslog.message.len()
                                    );
                                }
                            }
                            Ok(None) | Err(_) => {
                                stats.record_parse_error();
                            }
                        }
                    }
                    Err(DecodeError::Truncated) => {
                        stats.record_decode_truncated();
                    }
                    Err(DecodeError::Unsupported) => {
                        stats.record_decode_unsupported();
                    }
                    Err(DecodeError::FragmentedFirst) => {
                        stats.record_fragmented_first();
                    }
                }
            }
            Ok(None) => {
                consecutive_errors = 0;
                // Idle / read timeout: sleep briefly to avoid busy-loop
                clock.sleep(Duration::from_millis(10));
                continue;
            }
            Err(SnifferError::CaptureClosed(_)) => {
                debug!("Packet stream closed/exhausted, finishing capture loop");
                break;
            }
            Err(SnifferError::PersistentCapture(e)) => {
                error!("Fatal capture error: {}", e);
                return Err(SnifferError::PersistentCapture(e));
            }
            Err(e) => {
                consecutive_errors += 1;
                if clock.now().duration_since(last_error_log) >= Duration::from_secs(1) {
                    warn!("Capture error (consecutive={}): {}", consecutive_errors, e);
                    last_error_log = clock.now();
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
                clock.sleep(Duration::from_millis(10));
            }
        }
    }

    // In one-shot mode (!options.periodic), default to emitting an empty summary per Decisions table.
    // In periodic mode, only emit if emit_empty is set or stats is not empty.
    let should_emit = options.emit_empty || !options.periodic || !stats.is_empty();
    if should_emit {
        let window_end_time = clock.system_now();
        let window_duration_secs = clock
            .now()
            .duration_since(window_start_instant)
            .as_secs_f64();
        let interval_seconds = if options.periodic {
            window_duration_secs.round() as u64
        } else {
            options
                .duration
                .unwrap_or(window_duration_secs.round() as u64)
        };

        stats.set_capture_stats(source.stats());
        let summary = stats.get_summary(
            interval_seconds,
            window_duration_secs,
            window_start_time,
            window_end_time,
        );

        let json = match options.format {
            OutputFormat::Pretty => serde_json::to_string_pretty(&summary),
            OutputFormat::Ndjson => serde_json::to_string(&summary),
        }
        .map_err(|e| SnifferError::Capture(format!("JSON serialization failed: {}", e)))?;

        write_summary_json(&mut writer, &json)?;
    }

    Ok(())
}

fn write_summary_json<W: Write>(writer: &mut W, json: &str) -> Result<(), SnifferError> {
    if let Err(e) = writeln!(writer, "{}", json) {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            return Err(SnifferError::OutputClosed);
        }
        return Err(SnifferError::Capture(format!(
            "Failed to write output: {}",
            e
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::Datalink;
    use crate::error::SnifferError;
    use crate::stats::JsonSummary;
    use crate::PacketData;
    use std::collections::VecDeque;
    use std::io::Cursor;

    fn create_test_frame(payload: &[u8]) -> Vec<u8> {
        create_test_frame_with_port(514, payload)
    }

    fn pkt(data: Vec<u8>) -> PacketData<'static> {
        PacketData::owned(data)
    }

    fn create_test_frame_with_port(port: u16, payload: &[u8]) -> Vec<u8> {
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
        eth.extend_from_slice(&port.to_be_bytes());
        eth.extend_from_slice(&udp_len.to_be_bytes());
        eth.extend_from_slice(&[0x00, 0x00]);
        eth.extend_from_slice(payload);
        eth
    }

    fn default_test_options() -> RunOptions {
        RunOptions {
            duration: Some(1),
            frequency: 1,
            ..RunOptions::default()
        }
    }

    struct MockPacketSource {
        packets: VecDeque<Result<Option<PacketData<'static>>, SnifferError>>,
        datalink: Datalink,
    }

    impl MockPacketSource {
        fn new(packets: Vec<Result<Option<PacketData<'static>>, SnifferError>>) -> Self {
            Self {
                packets: packets.into(),
                datalink: Datalink::Ethernet,
            }
        }
    }

    impl PacketSource for MockPacketSource {
        fn next_packet(&mut self) -> Result<Option<PacketData<'_>>, SnifferError> {
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

    fn init_test_logger() {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .try_init();
    }

    #[test]
    fn test_run_sniffer_basic() {
        init_test_logger();
        init_logger();
        let config = default_test_options();

        let packet_data = create_test_frame(b"<13>Oct 11 22:14:15 mymachine su: su root");
        let packets = vec![Ok(Some(pkt(packet_data))), Ok(None)];

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
        let mut config = default_test_options();
        config.format = OutputFormat::Ndjson;

        let packet_data = create_test_frame(b"<13>Oct 11 22:14:15 mymachine su: su root");
        let packets = vec![Ok(Some(pkt(packet_data))), Ok(None)];

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
        let mut config = default_test_options();
        config.periodic = true;
        config.frequency = 1;

        let packet_data = create_test_frame(b"<13>Oct 11 22:14:15 mymachine su: su root");
        let packets = vec![
            Ok(Some(pkt(packet_data.clone()))),
            Ok(Some(pkt(packet_data))),
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
        let config = default_test_options();

        let packets = vec![
            Ok(Some(pkt(vec![0, 1, 2, 3]))), // Invalid frame
            Ok(Some(pkt(vec![]))),           // Empty
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
        assert_eq!(summary.decode_truncated, 2);
    }

    #[test]
    fn test_run_sniffer_dropped_packet_counters_for_each_path() {
        let config = default_test_options();

        // 1. Valid syslog packet
        let valid_packet = create_test_frame(b"<13>Oct 11 22:14:15 mymachine ok");

        // 2. Empty payload (parse error)
        let empty_payload_packet = create_test_frame(b"");

        // 3. Whitespace/NUL only payload (parse error)
        let whitespace_packet = create_test_frame(b"   \r\n\0  ");

        // 4. Truncated frame (decode truncated)
        let truncated_packet = vec![0x00; 10];

        // 5. Unsupported protocol, e.g. TCP instead of UDP (decode unsupported)
        let mut tcp_packet = create_test_frame(b"<13>test");
        tcp_packet[23] = 6; // IP protocol = 6 (TCP)

        // 6. Fragmented first packet (IPv4 MF flag set at byte 20, offset = 0)
        let mut first_frag = create_test_frame(b"<13>first fragment");
        first_frag[20] = 0x20; // MF flag set
        first_frag[21] = 0x00; // offset = 0

        // 7. Non-matching port (destination port 9999 instead of 514)
        let non_matching_packet = create_test_frame_with_port(9999, b"<13>wrong port");

        let packets = vec![
            Ok(Some(pkt(valid_packet))),
            Ok(Some(pkt(empty_payload_packet))),
            Ok(Some(pkt(whitespace_packet))),
            Ok(Some(pkt(truncated_packet))),
            Ok(Some(pkt(tcp_packet))),
            Ok(Some(pkt(first_frag))),
            Ok(Some(pkt(non_matching_packet))),
            Ok(None),
        ];

        let source = MockPacketSource::new(packets);
        let mut buf = Cursor::new(Vec::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        let res = run_sniffer_with_writer(config, source, &mut buf, shutdown);
        assert!(res.is_ok());

        let output = String::from_utf8(buf.into_inner()).unwrap();
        let summary: JsonSummary = serde_json::from_str(&output).expect("valid json");

        assert_eq!(summary.packets_seen, 7);
        assert_eq!(summary.datagrams_decoded, 3); // valid + empty + whitespace
        assert_eq!(summary.non_matching_port, 1);
        assert_eq!(summary.parse_errors, 2); // empty + whitespace
        assert_eq!(summary.decode_truncated, 1);
        assert_eq!(summary.decode_unsupported, 1);
        assert_eq!(summary.decode_errors, 2); // decode_truncated + decode_unsupported
        assert_eq!(summary.fragmented_first, 1);
        assert_eq!(summary.hosts.len(), 1);
        assert_eq!(summary.hosts["mymachine"].count, 1);
    }

    #[test]
    fn test_run_sniffer_no_sample_debug_logging() {
        init_test_logger();
        let mut config = default_test_options();
        config.sample_bytes = 0;

        let packet_data = create_test_frame(b"<13>Oct 11 22:14:15 mymachine SECRET_PASSWORD_123");
        let packets = vec![Ok(Some(pkt(packet_data))), Ok(None)];

        let source = MockPacketSource::new(packets);
        let mut buf = Cursor::new(Vec::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        let res = run_sniffer_with_writer(config, source, &mut buf, shutdown);
        assert!(res.is_ok());

        let output = String::from_utf8(buf.into_inner()).unwrap();
        let summary: JsonSummary = serde_json::from_str(&output).expect("valid json");
        assert_eq!(summary.hosts["mymachine"].sample, "");
    }

    #[test]
    fn test_run_sniffer_persistent_error() {
        init_test_logger();
        let mut config = default_test_options();
        config.duration = Some(10);
        config.frequency = 5;

        let packets: Vec<Result<Option<PacketData<'static>>, SnifferError>> = (0..50)
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
        let mut config = default_test_options();
        config.duration = Some(1000);

        let shutdown = Arc::new(AtomicBool::new(true)); // Already signalled
        let source = MockPacketSource::new(vec![]);
        let mut buf = Cursor::new(Vec::new());

        let res = run_sniffer_with_writer(config, source, &mut buf, shutdown);
        assert!(res.is_ok());
    }

    #[test]
    fn test_run_sniffer_validation_error() {
        let mut config = default_test_options();
        config.periodic = true;
        config.frequency = 10;
        config.duration = Some(2); // frequency > duration -> invalid!

        let source = MockPacketSource::new(vec![]);
        let mut buf = Cursor::new(Vec::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        let res = run_sniffer_with_writer(config, source, &mut buf, shutdown);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("Configuration error"));
    }

    struct FailingWriter {
        broken_pipe: bool,
    }

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            if self.broken_pipe {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "broken pipe",
                ))
            } else {
                Err(std::io::Error::other("write error"))
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_run_sniffer_broken_pipe_and_write_error() {
        let config = default_test_options();
        let packet = create_test_frame(b"<13>test msg");

        // BrokenPipe returns Err(SnifferError::OutputClosed)
        let source1 = MockPacketSource::new(vec![Ok(Some(pkt(packet.clone())))]);
        let writer1 = FailingWriter { broken_pipe: true };
        let shutdown1 = Arc::new(AtomicBool::new(false));
        let res1 = run_sniffer_with_writer(config.clone(), source1, writer1, shutdown1);
        assert!(matches!(res1, Err(SnifferError::OutputClosed)));

        // Other write error returns Err(SnifferError::Capture)
        let source2 = MockPacketSource::new(vec![Ok(Some(pkt(packet)))]);
        let writer2 = FailingWriter { broken_pipe: false };
        let shutdown2 = Arc::new(AtomicBool::new(false));
        let res2 = run_sniffer_with_writer(config, source2, writer2, shutdown2);
        assert!(res2.is_err());
        assert!(!matches!(res2, Err(SnifferError::OutputClosed)));
    }

    #[derive(Clone)]
    struct FakeClock {
        now: Arc<std::sync::Mutex<Instant>>,
        system_now: Arc<std::sync::Mutex<SystemTime>>,
    }

    impl FakeClock {
        fn new() -> Self {
            Self {
                now: Arc::new(std::sync::Mutex::new(Instant::now())),
                system_now: Arc::new(std::sync::Mutex::new(SystemTime::now())),
            }
        }

        fn advance(&self, d: Duration) {
            let mut now = self.now.lock().unwrap();
            *now += d;
            let mut sys = self.system_now.lock().unwrap();
            *sys += d;
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            *self.now.lock().unwrap()
        }
        fn sleep(&self, d: Duration) {
            self.advance(d);
        }
        fn system_now(&self) -> SystemTime {
            *self.system_now.lock().unwrap()
        }
    }

    #[test]
    fn test_run_sniffer_broken_pipe_periodic_indefinite_returns_promptly() {
        let mut config = default_test_options();
        config.periodic = true;
        config.frequency = 1;
        config.duration = None; // Indefinite periodic
        config.emit_empty = true;

        let writer = FailingWriter { broken_pipe: true };
        let shutdown = Arc::new(AtomicBool::new(false));
        let clock = FakeClock::new();

        struct PeriodicSleepingSource {
            called: usize,
            clock: FakeClock,
        }
        impl PacketSource for PeriodicSleepingSource {
            fn next_packet(&mut self) -> Result<Option<PacketData<'_>>, SnifferError> {
                self.called += 1;
                if self.called == 1 {
                    self.clock.advance(Duration::from_millis(1050));
                }
                Ok(None)
            }
            fn datalink(&self) -> Datalink {
                Datalink::Ethernet
            }
        }

        let res = run_sniffer_with_writer_and_clock(
            config,
            PeriodicSleepingSource {
                called: 0,
                clock: clock.clone(),
            },
            writer,
            shutdown,
            clock,
        );
        assert!(matches!(res, Err(SnifferError::OutputClosed)));
    }

    #[test]
    fn test_run_sniffer_emit_empty_and_periodic_ndjson() {
        let mut config = default_test_options();
        config.periodic = true;
        config.frequency = 1;
        config.format = OutputFormat::Ndjson;
        config.emit_empty = true;

        let source = MockPacketSource::new(vec![Ok(None)]);
        let mut buf = Cursor::new(Vec::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        let res = run_sniffer_with_writer(config, source, &mut buf, shutdown);
        assert!(res.is_ok());

        let output = String::from_utf8(buf.into_inner()).unwrap();
        assert!(output.contains("\"hosts\":{}"));
    }

    #[test]
    fn test_run_sniffer_top_level_wrapper() {
        let mut config = default_test_options();
        config.duration = Some(1);
        let source = MockPacketSource::new(vec![]);
        let res = run_sniffer(config, source);
        assert!(res.is_ok());
    }

    #[test]
    fn test_run_sniffer_periodic_interval_report() {
        let mut config = default_test_options();
        config.periodic = true;
        config.frequency = 1;
        config.duration = Some(2);
        config.emit_empty = true;
        config.format = OutputFormat::Ndjson;

        struct SleepingSource {
            count: usize,
            clock: FakeClock,
        }
        impl PacketSource for SleepingSource {
            fn next_packet(&mut self) -> Result<Option<PacketData<'_>>, SnifferError> {
                self.count += 1;
                if self.count == 1 {
                    self.clock.advance(Duration::from_millis(1100));
                    Ok(Some(pkt(create_test_frame(b"<13>test periodic periodic"))))
                } else {
                    self.clock.advance(Duration::from_millis(1000));
                    Ok(None)
                }
            }
            fn datalink(&self) -> Datalink {
                Datalink::Ethernet
            }
        }

        let clock = FakeClock::new();
        let source = SleepingSource {
            count: 0,
            clock: clock.clone(),
        };
        let mut buf = Cursor::new(Vec::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        let res =
            run_sniffer_with_writer_and_clock(config.clone(), source, &mut buf, shutdown, clock);
        assert!(res.is_ok());
        let output = String::from_utf8(buf.into_inner()).unwrap();
        assert!(output.contains("\"hosts\":"));

        // Test Pretty format in periodic interval
        let mut config_pretty = config.clone();
        config_pretty.format = OutputFormat::Pretty;
        let clock_pretty = FakeClock::new();
        let source_pretty = SleepingSource {
            count: 0,
            clock: clock_pretty.clone(),
        };
        let mut buf_pretty = Cursor::new(Vec::new());
        let res_pretty = run_sniffer_with_writer_and_clock(
            config_pretty,
            source_pretty,
            &mut buf_pretty,
            Arc::new(AtomicBool::new(false)),
            clock_pretty,
        );
        assert!(res_pretty.is_ok());

        // Test BrokenPipe in periodic interval
        let mut failing_writer = FailingWriter { broken_pipe: true };
        let clock_broken = FakeClock::new();
        let source_broken = SleepingSource {
            count: 0,
            clock: clock_broken.clone(),
        };
        let res_broken = run_sniffer_with_writer_and_clock(
            config,
            source_broken,
            &mut failing_writer,
            Arc::new(AtomicBool::new(false)),
            clock_broken,
        );
        assert!(matches!(res_broken, Err(SnifferError::OutputClosed)));
    }

    #[test]
    fn test_run_sniffer_duration_timeout() {
        let mut config = default_test_options();
        config.duration = Some(1);

        let clock = FakeClock::new();
        struct IdleSource(FakeClock);
        impl PacketSource for IdleSource {
            fn next_packet(&mut self) -> Result<Option<PacketData<'_>>, SnifferError> {
                self.0.advance(Duration::from_millis(500));
                Ok(None)
            }
            fn datalink(&self) -> Datalink {
                Datalink::Ethernet
            }
        }

        let mut buf = Cursor::new(Vec::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let res = run_sniffer_with_writer_and_clock(
            config,
            IdleSource(clock.clone()),
            &mut buf,
            shutdown,
            clock,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_run_sniffer_duration_zero_shutdown() {
        let mut config = default_test_options();
        config.duration = Some(0);
        config.emit_empty = true;

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();

        struct ShutdownSource(Arc<AtomicBool>);
        impl PacketSource for ShutdownSource {
            fn next_packet(&mut self) -> Result<Option<PacketData<'_>>, SnifferError> {
                self.0.store(true, Ordering::Relaxed);
                Ok(None)
            }
            fn datalink(&self) -> Datalink {
                Datalink::Ethernet
            }
        }

        let mut buf = Cursor::new(Vec::new());
        let res =
            run_sniffer_with_writer(config, ShutdownSource(shutdown_clone), &mut buf, shutdown);
        assert!(res.is_ok());
    }

    #[test]
    fn test_run_sniffer_non_matching_port_dropped() {
        let config = default_test_options(); // port: 514
        let frame514 = create_test_frame(b"<13>Oct 11 22:14:15 myhost syslog msg");
        let frame53 = create_test_frame_with_port(53, b"<13>Oct 11 22:14:15 dnsdecoy dns msg");

        let packets = vec![Ok(Some(pkt(frame514))), Ok(Some(pkt(frame53)))];

        let source = MockPacketSource::new(packets);
        let mut buf = Cursor::new(Vec::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        let res = run_sniffer_with_writer(config, source, &mut buf, shutdown);
        assert!(res.is_ok());

        let output = String::from_utf8(buf.into_inner()).unwrap();
        let summary: JsonSummary = serde_json::from_str(&output).expect("valid json");
        assert_eq!(summary.packets_seen, 2);
        assert_eq!(summary.datagrams_decoded, 1);
        assert_eq!(summary.non_matching_port, 1);
        assert!(summary.hosts.contains_key("myhost"));
        assert!(!summary.hosts.contains_key("dnsdecoy"));
    }

    #[test]
    fn test_run_sniffer_one_shot_empty_by_default() {
        let mut config = default_test_options();
        config.periodic = false;
        config.emit_empty = false;

        let source = MockPacketSource::new(vec![]);
        let mut buf = Cursor::new(Vec::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        let res = run_sniffer_with_writer(config, source, &mut buf, shutdown);
        assert!(res.is_ok());

        let output = String::from_utf8(buf.into_inner()).unwrap();
        let summary: JsonSummary = serde_json::from_str(&output).expect("valid json summary");
        assert_eq!(summary.packets_seen, 0);
        assert!(summary.hosts.is_empty());
    }

    #[test]
    fn test_run_sniffer_periodic_no_emit_empty_when_no_packets() {
        let mut config = default_test_options();
        config.periodic = true;
        config.emit_empty = false;
        config.frequency = 1;
        config.duration = Some(2);

        let clock = FakeClock::new();
        struct EmptySource(FakeClock);
        impl PacketSource for EmptySource {
            fn next_packet(&mut self) -> Result<Option<PacketData<'_>>, SnifferError> {
                self.0.advance(Duration::from_millis(1500));
                Ok(None)
            }
            fn datalink(&self) -> Datalink {
                Datalink::Ethernet
            }
        }

        let mut buf = Cursor::new(Vec::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let res = run_sniffer_with_writer_and_clock(
            config,
            EmptySource(clock.clone()),
            &mut buf,
            shutdown,
            clock,
        );
        assert!(res.is_ok());

        let output = String::from_utf8(buf.into_inner()).unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn test_run_sniffer_persistent_capture_fatal_immediately() {
        let config = default_test_options();
        let packets = vec![Err(SnifferError::PersistentCapture(
            "corrupt pcap".to_string(),
        ))];
        let source = MockPacketSource::new(packets);
        let mut buf = Cursor::new(Vec::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        let res = run_sniffer_with_writer(config, source, &mut buf, shutdown);
        assert!(matches!(res, Err(SnifferError::PersistentCapture(_))));
    }
}
