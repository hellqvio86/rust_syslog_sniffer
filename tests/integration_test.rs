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
    let mut stats = StatsTracker::new();
    stats.add_entry(packet.hostname.unwrap(), packet.message);

    // 4. Verify summary
    let summary = stats.get_summary(10);
    assert_eq!(summary.hosts.len(), 1);
    assert!(summary.hosts.contains_key("mymachine"));
    assert_eq!(summary.hosts["mymachine"].count, 1);
}
