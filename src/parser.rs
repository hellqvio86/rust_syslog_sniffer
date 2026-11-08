#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyslogPacket {
    pub message: String,
    pub hostname: Option<String>,
    pub is_non_utf8: bool,
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Parses a UDP syslog payload into a `SyslogPacket`.
///
/// Returns `None` only for empty payloads or payloads containing only whitespace/NULs.
/// Non-UTF-8 payloads are decoded lossily with `is_non_utf8 = true`.
pub fn parse_syslog_packet(packet: &[u8]) -> Option<SyslogPacket> {
    if packet.is_empty() {
        return None;
    }

    let is_non_utf8 = std::str::from_utf8(packet).is_err();
    let lossy = String::from_utf8_lossy(packet);
    let trimmed = lossy.trim_end_matches(['\r', '\n', '\0']);
    if trimmed.is_empty() {
        return None;
    }

    // Try parsing <PRI>
    let hostname = extract_hostname(trimmed);

    Some(SyslogPacket {
        message: trimmed.to_string(),
        hostname,
        is_non_utf8,
    })
}

fn extract_hostname(msg: &str) -> Option<String> {
    if !msg.starts_with('<') {
        return None;
    }

    let close_idx = msg.find('>')?;
    if !(2..=5).contains(&close_idx) {
        return None;
    }

    let pri_str = &msg[1..close_idx];
    let pri: u16 = pri_str.parse().ok()?;
    if pri > 191 {
        return None;
    }

    let rest = &msg[close_idx + 1..];

    // Case 1: RFC 5424: starts with "1 " (version 1)
    if rest.starts_with("1 ") {
        let mut parts = rest.split_ascii_whitespace();
        let _version = parts.next()?;
        let _timestamp = parts.next()?;
        if let Some(host) = parts.next() {
            if host == "-" || host.is_empty() {
                return None;
            }
            return Some(host.to_string());
        }
        return None;
    }

    // Case 2: RFC 3339 timestamp without version digit (e.g. rsyslog/syslog-ng)
    // Example: <34>2026-11-08T12:00:00+01:00 myhost app: msg
    if rest.len() >= 20 && rest.as_bytes()[0].is_ascii_digit() && rest.contains('T') {
        let mut parts = rest.split_ascii_whitespace();
        let ts = parts.next()?;
        if ts.contains('T') && ts.len() >= 19 {
            if let Some(host) = parts.next() {
                if is_valid_hostname(host) {
                    return Some(host.to_string());
                }
            }
            return None;
        }
    }

    // Case 3: RFC 3164 (BSD syslog): "Mmm  d hh:mm:ss host ..." or "Mmm dd hh:mm:ss host ..."
    // E.g. "Oct 11 22:14:15 mymachine su: ..."
    let rest_trimmed = rest.trim_start();
    if rest_trimmed.len() >= 15 {
        let month = &rest_trimmed[0..3];
        if MONTHS.contains(&month) && rest_trimmed.as_bytes()[3] == b' ' {
            // Find time field hh:mm:ss (look for colons)
            let mut parts = rest_trimmed.split_ascii_whitespace();
            let _month = parts.next()?;
            let _day = parts.next()?;
            let time = parts.next()?;
            if time.len() == 8 && time.as_bytes()[2] == b':' && time.as_bytes()[5] == b':' {
                if let Some(candidate) = parts.next() {
                    if is_valid_hostname(candidate) {
                        return Some(candidate.to_string());
                    }
                }
                return None;
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
        assert_eq!(pkt.hostname.as_deref(), Some("mymachine.example.com"));
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
        assert_eq!(pkt.hostname.as_deref(), Some("mymachine"));
    }

    #[test]
    fn test_rfc3164_single_digit_day() {
        let data = b"<13>Oct  1 22:14:15 mymachine su: su root";
        let pkt = parse_syslog_packet(data).unwrap();
        assert_eq!(pkt.hostname.as_deref(), Some("mymachine"));
    }

    #[test]
    fn test_rfc3164_without_body() {
        let data = b"<13>Oct 11 22:14:15 myhost";
        let pkt = parse_syslog_packet(data).unwrap();
        assert_eq!(pkt.hostname.as_deref(), Some("myhost"));
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
        assert_eq!(pkt.hostname.as_deref(), Some("myhost"));
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
        assert_eq!(pkt.hostname.as_deref(), Some("mymachine"));
        assert!(pkt.is_non_utf8);
        assert!(pkt.message.contains("mymachine bad"));
    }

    #[test]
    fn test_empty_payload() {
        assert!(parse_syslog_packet(b"").is_none());
        assert!(parse_syslog_packet(b"\r\n\0").is_none());
    }
}
