mod common;

use clap::Parser;
use common::{craft_ethernet_ipv4_udp, write_test_pcap};
use syslog_sniffer::config::Config;
use syslog_sniffer::parse_syslog_packet;
use syslog_sniffer::stats::{JsonSummary, StatsTracker};

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
        packet.hostname,
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

    // Create a pcap with two packets: one to port 514, one to port 53 (P0-2 decoy test)
    let pkt514 = craft_ethernet_ipv4_udp(514, b"<13>Oct 11 22:14:15 host514 test payload");
    let pkt53 = craft_ethernet_ipv4_udp(53, b"<13>Oct 11 22:14:15 dnsdecoy decoy payload");

    let path = std::env::temp_dir().join(format!("test_int_pcap_{}.pcap", std::process::id()));
    write_test_pcap(&path, 1, &[&pkt514, &pkt53]);

    // Test 1: Run with default port (514) -> only host514 should appear
    let out514 = std::process::Command::new(bin)
        .args(["--read-pcap", path.to_str().unwrap(), "--interval", "1"])
        .output()
        .expect("run binary with pcap");
    assert!(out514.status.success());
    let stdout514 = String::from_utf8_lossy(&out514.stdout);
    let stderr514 = String::from_utf8_lossy(&out514.stderr);
    assert!(stderr514.contains("The --interval argument is deprecated"));
    let summary514: JsonSummary = serde_json::from_str(&stdout514).expect("parse stdout json");
    assert!(summary514.hosts.contains_key("host514"));
    assert!(!summary514.hosts.contains_key("dnsdecoy"));
    assert_eq!(summary514.hosts["host514"].count, 1);

    // Test 2: Run with --port 53 -> only dnsdecoy should appear
    let out53 = std::process::Command::new(bin)
        .args([
            "--read-pcap",
            path.to_str().unwrap(),
            "--port",
            "53",
            "--interval",
            "1",
        ])
        .output()
        .expect("run binary with pcap port 53");
    assert!(out53.status.success());
    let stdout53 = String::from_utf8_lossy(&out53.stdout);
    let summary53: JsonSummary = serde_json::from_str(&stdout53).expect("parse stdout json");
    assert!(summary53.hosts.contains_key("dnsdecoy"));
    assert!(!summary53.hosts.contains_key("host514"));
    assert_eq!(summary53.hosts["dnsdecoy"].count, 1);

    // Test 3: Unsupported datalink fails fast (P1-8)
    let unsupp_path =
        std::env::temp_dir().join(format!("test_int_unsupp_{}.pcap", std::process::id()));
    write_test_pcap(&unsupp_path, 105, &[]);
    let out_unsupp = std::process::Command::new(bin)
        .args(["--read-pcap", unsupp_path.to_str().unwrap()])
        .output()
        .expect("run binary with unsupported linktype");
    assert!(!out_unsupp.status.success());
    let _ = std::fs::remove_file(&unsupp_path);

    // Test 4: Missing file fails fast
    let out_missing = std::process::Command::new(bin)
        .args(["--read-pcap", "/non/existent/path/never/pcap.pcap"])
        .output()
        .expect("run binary with missing file");
    assert!(!out_missing.status.success());

    let _ = std::fs::remove_file(&path);
}
