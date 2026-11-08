use clap::Parser;
use syslog_sniffer::config::Config;
use syslog_sniffer::parse_syslog_packet;
use syslog_sniffer::stats::StatsTracker;

#[test]
fn test_full_flow_simulation() {
    // 1. Parse config (simulate args)
    let args = vec!["syslog_sniffer", "--interface", "lo", "--port", "5140"];
    let config = Config::parse_from(args);
    assert_eq!(config.port, 5140);

    // 2. Simulate packet capture and parsing
    let raw_packet = "<13>Oct 11 22:14:15 mymachine su: su root".as_bytes();
    let packet = parse_syslog_packet(raw_packet).expect("Should parse");

    // 3. Track stats
    let mut stats = StatsTracker::default();
    stats.add_entry(
        packet.hostname.as_deref(),
        "127.0.0.1".parse().unwrap(),
        &packet.message,
        packet.is_non_utf8,
    );

    // 4. Verify summary
    let now = std::time::SystemTime::now();
    let summary = stats.get_summary(10, 10.0, now, now);
    assert_eq!(summary.schema_version, 1);
    assert_eq!(summary.hosts.len(), 1);
    assert!(summary.hosts.contains_key("mymachine"));
    assert_eq!(summary.hosts["mymachine"].count, 1);
}

#[test]
fn test_cli_binary_execution() {
    let bin = env!("CARGO_BIN_EXE_syslog_sniffer");
    let output = std::process::Command::new(bin)
        .arg("--help")
        .output()
        .expect("run binary --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("syslog_sniffer"));

    // Create a dummy pcap file to execute the full main() lifecycle
    let dummy_pkt = vec![0x00; 14];
    let mut file_bytes = Vec::new();
    file_bytes.extend_from_slice(&0xa1b2c3d4u32.to_ne_bytes());
    file_bytes.extend_from_slice(&2u16.to_ne_bytes());
    file_bytes.extend_from_slice(&4u16.to_ne_bytes());
    file_bytes.extend_from_slice(&0i32.to_ne_bytes());
    file_bytes.extend_from_slice(&0u32.to_ne_bytes());
    file_bytes.extend_from_slice(&65535u32.to_ne_bytes());
    file_bytes.extend_from_slice(&1u32.to_ne_bytes());

    file_bytes.extend_from_slice(&1700000000u32.to_ne_bytes());
    file_bytes.extend_from_slice(&0u32.to_ne_bytes());
    let len = dummy_pkt.len() as u32;
    file_bytes.extend_from_slice(&len.to_be_bytes());
    file_bytes.extend_from_slice(&len.to_be_bytes());
    file_bytes.extend_from_slice(&dummy_pkt);

    let path = std::env::temp_dir().join(format!("test_int_pcap_{}.pcap", std::process::id()));
    std::fs::write(&path, file_bytes).expect("write temp pcap");

    let out = std::process::Command::new(bin)
        .args(["--read-pcap", path.to_str().unwrap(), "--interval", "1"])
        .output()
        .expect("run binary with pcap");
    assert!(out.status.success());

    let _ = std::fs::remove_file(&path);
}
