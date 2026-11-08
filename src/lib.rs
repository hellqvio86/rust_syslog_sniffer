#![forbid(unsafe_code)]

pub mod app;
pub mod capture;
pub mod config;
pub mod decode;
pub mod error;
pub mod parser;
pub mod stats;

pub use decode::{decode_datagram, Datagram, Datalink};
pub use error::SnifferError;
pub use parser::{parse_syslog_packet, SyslogPacket};

#[derive(Debug, Clone, PartialEq)]
pub struct PacketData {
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureStats {
    pub packets_received: u32,
    pub packets_dropped: u32,
    pub packets_if_dropped: u32,
}

pub trait PacketSource {
    fn next_packet(&mut self) -> Result<Option<PacketData>, SnifferError>;
    fn datalink(&self) -> Datalink {
        Datalink::Raw
    }
    fn stats(&mut self) -> Option<CaptureStats> {
        None
    }
    fn get_datalink(&self) -> String {
        format!("{:?}", self.datalink())
    }
}

impl<T: PacketSource + ?Sized> PacketSource for Box<T> {
    fn next_packet(&mut self) -> Result<Option<PacketData>, SnifferError> {
        (**self).next_packet()
    }
    fn datalink(&self) -> Datalink {
        (**self).datalink()
    }
    fn stats(&mut self) -> Option<CaptureStats> {
        (**self).stats()
    }
    fn get_datalink(&self) -> String {
        (**self).get_datalink()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MinimalSource {
        returned: bool,
    }

    impl PacketSource for MinimalSource {
        fn next_packet(&mut self) -> Result<Option<PacketData>, SnifferError> {
            if !self.returned {
                self.returned = true;
                Ok(Some(PacketData {
                    data: vec![1, 2, 3],
                }))
            } else {
                Ok(None)
            }
        }
    }

    #[test]
    fn test_packet_source_defaults_and_box() {
        let mut source: Box<dyn PacketSource> = Box::new(MinimalSource { returned: false });
        assert_eq!(source.datalink(), Datalink::Raw);
        assert_eq!(source.get_datalink(), "Raw");
        assert_eq!(source.stats(), None);

        let p1 = source.next_packet().unwrap();
        assert_eq!(
            p1,
            Some(PacketData {
                data: vec![1, 2, 3]
            })
        );
        let p2 = source.next_packet().unwrap();
        assert_eq!(p2, None);
    }
}
