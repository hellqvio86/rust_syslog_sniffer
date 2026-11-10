use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyslogPacket<'a> {
    pub message: Cow<'a, str>,
    pub hostname: Option<&'a str>,
    pub is_non_utf8: bool,
}

const MONTHS: [&[u8]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

/// Parses a UDP syslog payload into a `SyslogPacket`.
///
/// Returns `None` only for empty payloads or payloads containing only whitespace/NULs.
/// Non-UTF-8 payloads are decoded lossily with `is_non_utf8 = true`.
pub fn parse_syslog_packet<'a>(packet: &'a [u8]) -> Option<SyslogPacket<'a>> {
    if packet.is_empty() || packet.iter().all(|&b| b.is_ascii_whitespace() || b == 0) {
        return None;
    }

    match std::str::from_utf8(packet) {
        Ok(s) => {
            let trimmed = s.trim_end_matches(['\r', '\n', '\0']);
            if trimmed
                .trim_matches(|c: char| c.is_whitespace() || c == '\0')
                .is_empty()
            {
                return None;
            }
            let hostname = extract_hostname(trimmed);
            Some(SyslogPacket {
                message: Cow::Borrowed(trimmed),
                hostname,
                is_non_utf8: false,
            })
        }
        Err(e) => {
            let lossy = String::from_utf8_lossy(packet);
            let trimmed = lossy.trim_end_matches(['\r', '\n', '\0']);
            if trimmed
                .trim_matches(|c: char| c.is_whitespace() || c == '\0')
                .is_empty()
            {
                return None;
            }
            let valid_prefix = std::str::from_utf8(&packet[..e.valid_up_to()]).unwrap_or("");
            let hostname = extract_hostname(valid_prefix);
            Some(SyslogPacket {
                message: Cow::Owned(trimmed.to_string()),
                hostname,
                is_non_utf8: true,
            })
        }
    }
}

fn extract_hostname(msg: &str) -> Option<&str> {
    if !msg.starts_with('<') {
        return None;
    }

    let close_idx = msg.find('>')?;
    if !(2..=5).contains(&close_idx) {
        return None;
    }

    let pri_str = msg.get(1..close_idx)?;
    let pri: u16 = pri_str.parse().ok()?;
    if pri > 191 {
        return None;
    }

    let rest = msg.get(close_idx + 1..)?;

    // Case 1: RFC 5424: starts with "1 " (version 1)
    if rest.starts_with("1 ") {
        let mut parts = rest.split_ascii_whitespace();
        let _version = parts.next()?;
        let _timestamp = parts.next()?;
        if let Some(host) = parts.next() {
            if host == "-" || host.is_empty() {
                return None;
            }
            return Some(host);
        }
        return None;
    }

    // Case 2: RFC 3339 timestamp without version digit (e.g. rsyslog/syslog-ng)
    // Example: <34>2026-11-08T12:00:00+01:00 myhost app: msg
    if rest.len() >= 20
        && rest.as_bytes().first().is_some_and(u8::is_ascii_digit)
        && rest.contains('T')
    {
        let mut parts = rest.split_ascii_whitespace();
        let ts = parts.next()?;
        if ts.contains('T') && ts.len() >= 19 {
            if let Some(host) = parts.next() {
                if is_valid_hostname(host) {
                    return Some(host);
                }
            }
            return None;
        }
    }

    // Case 3: RFC 3164 (BSD syslog): "Mmm  d hh:mm:ss host ..." or "Mmm dd hh:mm:ss host ..."
    // E.g. "Oct 11 22:14:15 mymachine su: ..."
    let rest_trimmed = rest.trim_start();
    if rest_trimmed.len() >= 15 {
        if let Some(month) = rest_trimmed.as_bytes().get(0..3) {
            if MONTHS.contains(&month) && rest_trimmed.as_bytes().get(3) == Some(&b' ') {
                // Find time field hh:mm:ss (look for colons)
                let mut parts = rest_trimmed.split_ascii_whitespace();
                let _month = parts.next()?;
                let _day = parts.next()?;
                let time = parts.next()?;
                if time.len() == 8
                    && time.as_bytes().get(2) == Some(&b':')
                    && time.as_bytes().get(5) == Some(&b':')
                {
                    if let Some(candidate) = parts.next() {
                        if is_valid_hostname(candidate) {
                            return Some(candidate);
                        }
                    }
                    return None;
                }
            }
        }
    }

    None
}

fn is_valid_hostname(candidate: &str) -> bool {
    if candidate.is_empty() || candidate == "-" {
        return false;
    }
    // A tag like "su:" or "sshd[123]:" is NOT a hostname
    if candidate.ends_with(':') || candidate.contains('[') || candidate.contains(']') {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc5424_valid() {
        let data = b"<165>1 2026-11-08T22:14:15.003Z mymachine.example.com appname 123 ID47 - Test";
        let pkt = parse_syslog_packet(data).unwrap();
        assert_eq!(pkt.hostname, Some("mymachine.example.com"));
        assert_eq!(pkt.message, std::str::from_utf8(data).unwrap());
        assert!(!pkt.is_non_utf8);
    }

    #[test]
    fn test_rfc5424_nilvalue_hostname() {
        let data = b"<165>1 2026-11-08T22:14:15.003Z - appname 123 ID47 - Test";
        let pkt = parse_syslog_packet(data).unwrap();
        assert_eq!(pkt.hostname, None);
    }

    #[test]
    fn test_rfc3164_with_hostname() {
        let data = b"<13>Oct 11 22:14:15 mymachine su: su root";
        let pkt = parse_syslog_packet(data).unwrap();
        assert_eq!(pkt.hostname, Some("mymachine"));
    }

    #[test]
    fn test_rfc3164_single_digit_day() {
        let data = b"<13>Oct  1 22:14:15 mymachine su: su root";
        let pkt = parse_syslog_packet(data).unwrap();
        assert_eq!(pkt.hostname, Some("mymachine"));
    }

    #[test]
    fn test_rfc3164_without_body() {
        let data = b"<13>Oct 11 22:14:15 myhost";
        let pkt = parse_syslog_packet(data).unwrap();
        assert_eq!(pkt.hostname, Some("myhost"));
    }

    #[test]
    fn test_rfc3164_missing_hostname_tag_only() {
        // Tag "su:" must NOT be parsed as a hostname
        let data = b"<13>Oct 11 22:14:15 su: su root";
        let pkt = parse_syslog_packet(data).unwrap();
        assert_eq!(pkt.hostname, None);
    }

    #[test]
    fn test_rfc3164_missing_hostname_tag_with_pid() {
        let data = b"<13>Oct 11 22:14:15 sshd[123]: session opened";
        let pkt = parse_syslog_packet(data).unwrap();
        assert_eq!(pkt.hostname, None);
    }

    #[test]
    fn test_rfc3339_rsyslog_without_version() {
        let data = b"<34>2026-11-08T12:00:00.123456+01:00 myhost tag: msg";
        let pkt = parse_syslog_packet(data).unwrap();
        assert_eq!(pkt.hostname, Some("myhost"));
    }

    #[test]
    fn test_pri_out_of_range() {
        let data = b"<192>Oct 11 22:14:15 mymachine su: su root";
        let pkt = parse_syslog_packet(data).unwrap();
        assert_eq!(pkt.hostname, None);
    }

    #[test]
    fn test_trailing_newline_and_null_trimmed() {
        let data = b"<13>Oct 11 22:14:15 mymachine hello\r\n\0";
        let pkt = parse_syslog_packet(data).unwrap();
        assert_eq!(pkt.message, "<13>Oct 11 22:14:15 mymachine hello");
    }

    #[test]
    fn test_non_utf8_decoded_lossy() {
        let data = b"<13>Oct 11 22:14:15 mymachine bad \xFF byte";
        let pkt = parse_syslog_packet(data).unwrap();
        assert_eq!(pkt.hostname, Some("mymachine"));
        assert!(pkt.is_non_utf8);
        assert!(pkt.message.contains("mymachine bad"));
    }

    #[test]
    fn test_empty_payload() {
        assert!(parse_syslog_packet(b"").is_none());
        assert!(parse_syslog_packet(b"\r\n\0").is_none());
        assert!(parse_syslog_packet(b"   \r\n\0  ").is_none());
    }

    #[test]
    fn test_parser_edge_cases() {
        // Plain text without '<'
        let pkt1 = parse_syslog_packet(b"plain text message").unwrap();
        assert_eq!(pkt1.hostname, None);

        // Incomplete PRI brackets
        let pkt2 = parse_syslog_packet(b"<13incomplete").unwrap();
        assert_eq!(pkt2.hostname, None);

        // Empty PRI '<>'
        let pkt3 = parse_syslog_packet(b"<>test").unwrap();
        assert_eq!(pkt3.hostname, None);

        // Too long PRI '<123456>'
        let pkt4 = parse_syslog_packet(b"<123456>test").unwrap();
        assert_eq!(pkt4.hostname, None);

        // Non-numeric PRI '<abc>'
        let pkt5 = parse_syslog_packet(b"<abc>test").unwrap();
        assert_eq!(pkt5.hostname, None);

        // RFC 5424 incomplete header (version without timestamp)
        let pkt6 = parse_syslog_packet(b"<14>1 ").unwrap();
        assert_eq!(pkt6.hostname, None);

        // RFC 5424 with timestamp but no hostname
        let pkt7 = parse_syslog_packet(b"<14>1 2026-11-08T12:00:00Z").unwrap();
        assert_eq!(pkt7.hostname, None);

        // RFC 3339 with tag instead of hostname
        let pkt8 = parse_syslog_packet(b"<34>2026-11-08T12:00:00Z su: test").unwrap();
        assert_eq!(pkt8.hostname, None);

        // RFC 3164 with only timestamp
        let pkt9 = parse_syslog_packet(b"<13>Oct 11 22:14:15").unwrap();
        assert_eq!(pkt9.hostname, None);

        // RFC 3164 where candidate hostname is "-"
        let pkt10 = parse_syslog_packet(b"<13>Oct 11 22:14:15 - test message").unwrap();
        assert_eq!(pkt10.hostname, None);

        // Non-UTF-8 payload in parse_syslog_packet
        let pkt11 = parse_syslog_packet(b"<13>\xff\xfe non utf8").unwrap();
        assert!(pkt11.is_non_utf8);

        let pkt12 = parse_syslog_packet(b"<13>valid utf8").unwrap();
        assert!(!pkt12.is_non_utf8);
        assert_eq!(pkt12.message, "<13>valid utf8");
    }

    #[test]
    fn test_p0_1_multibyte_at_all_offsets_never_panics() {
        // Specific reproducer from P0-1
        let repro = b"<13>\xC3\x96\xF0\x9F\x98\x80xxxxxxxxxxxxx";
        let pkt = parse_syslog_packet(repro);
        assert!(pkt.is_some());

        // 2-byte (Ö: \xC3\x96), 3-byte (€: \xE2\x82\xAC), 4-byte (😀: \xF0\x9F\x98\x80), and lossy invalid bytes
        let multibyte_samples: &[&[u8]] = &[
            "Ö".as_bytes(),
            "€".as_bytes(),
            "😀".as_bytes(),
            &[0xff, 0xfe],
            &[0x80, 0x81, 0x82],
        ];

        for sample in multibyte_samples {
            for offset in 0..=20 {
                let mut data = Vec::new();
                data.extend_from_slice(b"<13>");
                data.resize(data.len() + offset, b'a');
                data.extend_from_slice(sample);
                data.extend_from_slice(b"xxxxxxxxxxxxxxxxxxxx");

                let res = parse_syslog_packet(&data);
                assert!(res.is_some());
            }
        }
    }

    #[test]
    fn test_parser_table_edge_cases() {
        // PRI <0>
        let pkt_pri0 = parse_syslog_packet(b"<0>Oct 11 22:14:15 myhost msg").unwrap();
        assert_eq!(pkt_pri0.hostname, Some("myhost"));

        // PRI <1> (single digit)
        let pkt_pri1 = parse_syslog_packet(b"<1>Oct 11 22:14:15 myhost msg").unwrap();
        assert_eq!(pkt_pri1.hostname, Some("myhost"));

        // PRI <191>
        let pkt_pri191 = parse_syslog_packet(b"<191>Oct 11 22:14:15 myhost msg").unwrap();
        assert_eq!(pkt_pri191.hostname, Some("myhost"));

        // Hostname 255+ bytes
        let long_host = "h".repeat(300);
        let msg = format!("<13>Oct 11 22:14:15 {} msg", long_host);
        let pkt_long = parse_syslog_packet(msg.as_bytes()).unwrap();
        assert_eq!(pkt_long.hostname, Some(long_host.as_str()));

        // RFC 5424 with structured data containing spaces
        let sdata_msg = b"<165>1 2026-11-08T22:14:15.003Z myhost app 123 ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] Test message";
        let pkt_sdata = parse_syslog_packet(sdata_msg).unwrap();
        assert_eq!(pkt_sdata.hostname, Some("myhost"));
    }
}
