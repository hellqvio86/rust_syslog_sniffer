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
}
