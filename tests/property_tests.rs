use proptest::prelude::*;
use std::net::IpAddr;
use std::time::SystemTime;
use syslog_sniffer::config::KeyBy;
use syslog_sniffer::decode::{decode_datagram, Datalink};
use syslog_sniffer::parser::parse_syslog_packet;
use syslog_sniffer::stats::{JsonSummary, StatsTracker};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn test_parse_syslog_packet_invariants(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        if let Some(parsed) = parse_syslog_packet(&data) {
            if let Some(hostname) = parsed.hostname {
                prop_assert!(hostname.len() <= data.len());
            }
            // Message string shouldn't exceed lossy UTF-8 expansion (up to 3x)
            prop_assert!(parsed.message.len() <= data.len().saturating_mul(4) + 16);
        }
    }

    #[test]
    fn test_decode_datagram_invariants(
        datalink_choice in 0u8..6,
        frame in prop::collection::vec(any::<u8>(), 0..4096),
    ) {
        let datalink = match datalink_choice {
            0 => Datalink::Ethernet,
            1 => Datalink::LinuxSll,
            2 => Datalink::LinuxSll2,
            3 => Datalink::Raw,
            4 => Datalink::NullLoop,
            _ => Datalink::Unsupported(999),
        };

        if let Ok(datagram) = decode_datagram(datalink, &frame) {
            let frame_start = frame.as_ptr() as usize;
            let frame_end = frame_start + frame.len();
            let payload_start = datagram.payload.as_ptr() as usize;
            let payload_end = payload_start + datagram.payload.len();

            if !datagram.payload.is_empty() {
                prop_assert!(payload_start >= frame_start, "payload start {} < frame start {}", payload_start, frame_start);
                prop_assert!(payload_end <= frame_end, "payload end {} > frame end {}", payload_end, frame_end);
            }
        }
    }

    #[test]
    fn test_json_summary_reparses_invariants(
        max_hosts in 1usize..20,
        max_sources in 1usize..20,
        sample_bytes in 0usize..256,
        key_by_source_ip in any::<bool>(),
        records in prop::collection::vec(
            (
                any::<Option<String>>(),
                prop::collection::vec(any::<u8>(), 0..256),
                prop::collection::vec(any::<u8>(), 4..=4),
                any::<bool>(),
            ),
            0..30
        ),
        packets_seen in 0u64..1000,
        datagrams_decoded in 0u64..1000,
        truncated in 0u64..10,
        unsupported in 0u64..10,
        fragmented in 0u64..10,
        parse_errs in 0u64..10,
        non_matching in 0u64..10,
    ) {
        let key_by = if key_by_source_ip {
            KeyBy::SourceIp
        } else {
            KeyBy::Hostname
        };
        let mut tracker = StatsTracker::new(max_hosts, max_sources, sample_bytes, key_by);

        for _ in 0..packets_seen {
            tracker.record_packet_seen();
        }
        for _ in 0..datagrams_decoded {
            tracker.record_datagram_decoded();
        }
        for _ in 0..truncated {
            tracker.record_decode_truncated();
        }
        for _ in 0..unsupported {
            tracker.record_decode_unsupported();
        }
        for _ in 0..fragmented {
            tracker.record_fragmented_first();
        }
        for _ in 0..parse_errs {
            tracker.record_parse_error();
        }
        for _ in 0..non_matching {
            tracker.record_non_matching_port();
        }

        for (hostname_opt, msg_bytes, ip_bytes, is_lossy) in records {
            let msg = String::from_utf8_lossy(&msg_bytes);
            let ip = IpAddr::from([ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]]);
            let hostname = hostname_opt.as_deref();
            tracker.add_entry(hostname, ip, &msg, is_lossy);
        }

        let summary = tracker.get_summary(
            10,
            1.234,
            SystemTime::UNIX_EPOCH,
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(10),
        );

        let json_compact = serde_json::to_string(&summary).expect("compact serialization failed");
        let reparsed_compact: JsonSummary = serde_json::from_str(&json_compact).expect("compact deserialization failed");
        prop_assert_eq!(&summary, &reparsed_compact);

        let json_pretty = serde_json::to_string_pretty(&summary).expect("pretty serialization failed");
        let reparsed_pretty: JsonSummary = serde_json::from_str(&json_pretty).expect("pretty deserialization failed");
        prop_assert_eq!(&summary, &reparsed_pretty);
    }
}
