pub mod app;
pub mod capture;
pub mod config;
pub mod stats;

use regex::Regex;
use serde::Serialize;
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq)]
pub struct PacketData {
    pub data: Vec<u8>,
}

pub trait PacketSource {
    fn next_packet(&mut self) -> Result<Option<PacketData>, String>;
    fn get_datalink(&self) -> String;
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct SyslogPacket {
    pub message: String,
    pub hostname: Option<String>,
}

fn rfc5424_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        // <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCT-DATA MSG
        // We just want to grab the HOSTNAME (4th field)
        // Example: <165>1 2003-10-11T22:14:15.003Z mymachine.example.com ...
        Regex::new(r"^<(\d{1,3})>(\d)\s+(\S+)\s+(\S+)\s+").unwrap()
    })
}

fn rfc3164_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        // <PRI>TIMESTAMP HOSTNAME MSG
        // Example: <13>Oct 11 22:14:15 mymachine su: ...
        Regex::new(r"^<(\d{1,3})>([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+").unwrap()
    })
}

pub fn parse_syslog_packet(packet: &[u8]) -> Option<SyslogPacket> {
    if packet.is_empty() {
        return None;
    }

    match std::str::from_utf8(packet) {
        Ok(s) => {
            let mut hostname = None;

            // Try RFC 5424
            if let Some(caps) = rfc5424_regex().captures(s) {
                if let Some(host) = caps.get(4) {
                    hostname = Some(host.as_str().to_string());
                }
            }
            // Try RFC 3164
            else if let Some(caps) = rfc3164_regex().captures(s) {
                if let Some(host) = caps.get(3) {
                    hostname = Some(host.as_str().to_string());
                }
            }

            Some(SyslogPacket {
                message: s.to_string(),
                hostname,
            })
        }
        Err(_) => None,
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
    #[test]
    fn test_parse_no_hostname() {
        let data = "Simple message".as_bytes();
        let packet = parse_syslog_packet(data).unwrap();
        assert_eq!(packet.message, "Simple message");
        assert!(packet.hostname.is_none());
    }

    #[test]
    fn test_debug_impls() {
        let packet = SyslogPacket {
            message: "msg".to_string(),
            hostname: Some("host".to_string()),
        };
        let debug_str = format!("{:?}", packet);
        assert!(debug_str.contains("SyslogPacket"));
        assert!(debug_str.contains("msg"));
        assert!(debug_str.contains("host"));

        let packet_clone = packet.clone();
        assert_eq!(packet, packet_clone);

        let data = PacketData {
            data: vec![1, 2, 3],
        };
        let data_debug = format!("{:?}", data);
        assert!(data_debug.contains("PacketData"));
        let data_clone = data.clone();
        assert_eq!(data, data_clone);
    }
}
