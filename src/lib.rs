
pub struct SyslogPacket {
    pub message: String,
}

pub fn parse_syslog_packet(packet: &[u8]) -> Option<SyslogPacket> {
    // Basic parsing: assume the payload is the message.
    // In a real syslog packet, there might be headers, but for this simple sniffer,
    // we'll treat the whole payload as the message if it's valid UTF-8.
    
    // Syslog over UDP (RFC 5426) usually just sends the message.
    // The message often starts with <PRI> but we can just print the whole thing.
    
    if packet.is_empty() {
        return None;
    }

    match std::str::from_utf8(packet) {
        Ok(s) => Some(SyslogPacket {
            message: s.to_string(),
        }),
        Err(_) => None, // Not valid UTF-8, maybe not a text syslog message
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_syslog() {
        let data = "<13>Hello world".as_bytes();
        let packet = parse_syslog_packet(data).unwrap();
        assert_eq!(packet.message, "<13>Hello world");
    }

    #[test]
    fn test_parse_empty() {
        let data = [].as_slice();
        assert!(parse_syslog_packet(data).is_none());
    }

    #[test]
    fn test_parse_invalid_utf8() {
        let data = [0xff, 0xff, 0xff];
        assert!(parse_syslog_packet(&data).is_none());
    }
}
