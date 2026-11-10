#![no_main]
use libfuzzer_sys::fuzz_target;
use syslog_sniffer::parse_syslog_packet;

fuzz_target!(|data: &[u8]| {
    if let Some(parsed) = parse_syslog_packet(data) {
        if let Some(ref hostname) = parsed.hostname {
            assert!(hostname.len() <= data.len());
        }
    }
});
