#![forbid(unsafe_code)]

pub mod app;
pub mod capture;
pub mod config;
pub mod decode;
pub mod error;
pub mod parser;
pub mod stats;

pub use app::{Clock, RealClock};
pub use config::{Config, KeyBy, OutputFormat, RunOptions};
pub use decode::{decode_datagram, Datagram, Datalink, DecodeError};
pub use error::SnifferError;
pub use parser::{parse_syslog_packet, SyslogPacket};
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq)]
pub struct PacketData<'a> {
    pub data: Cow<'a, [u8]>,
}

impl<'a> PacketData<'a> {
    pub fn new(data: impl Into<Cow<'a, [u8]>>) -> Self {
        Self { data: data.into() }
    }

    pub fn borrowed(data: &'a [u8]) -> Self {
        Self {
            data: Cow::Borrowed(data),
        }
    }

    pub fn owned(data: Vec<u8>) -> Self {
        Self {
            data: Cow::Owned(data),
        }
    }
}

impl<'a> From<Vec<u8>> for PacketData<'a> {
    fn from(data: Vec<u8>) -> Self {
        Self::owned(data)
    }
}

impl<'a> From<&'a [u8]> for PacketData<'a> {
    fn from(data: &'a [u8]) -> Self {
        Self::borrowed(data)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureStats {
    pub packets_received: u32,
    pub packets_dropped: u32,
    pub packets_if_dropped: u32,
}

/// Abstraction for a packet capture source (live raw socket or offline pcap file).
///
/// # Lifetimes and Processing Contract
/// `next_packet()` yields `PacketData<'_>` with a lifetime tied to the source.
/// Callers **must** fully process or copy the packet data before the next invocation
/// of `next_packet()` (classic pcap ring buffer / packet memory reuse constraint).
pub trait PacketSource {
    /// Returns the next packet, `Ok(None)` on non-blocking timeout, or error.
    ///
    /// The returned `PacketData` may borrow internal buffers that will be overwritten
    /// on subsequent calls. Callers must finish processing before calling `next_packet` again.
    fn next_packet(&mut self) -> Result<Option<PacketData<'_>>, SnifferError>;
    fn datalink(&self) -> Datalink {
        Datalink::Raw
    }
    fn stats(&mut self) -> Option<CaptureStats> {
        None
    }
}

impl<T: PacketSource + ?Sized> PacketSource for Box<T> {
    fn next_packet(&mut self) -> Result<Option<PacketData<'_>>, SnifferError> {
        (**self).next_packet()
    }
    fn datalink(&self) -> Datalink {
        (**self).datalink()
    }
    fn stats(&mut self) -> Option<CaptureStats> {
        (**self).stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MinimalSource {
        returned: bool,
    }

    impl PacketSource for MinimalSource {
        fn next_packet(&mut self) -> Result<Option<PacketData<'_>>, SnifferError> {
            if !self.returned {
                self.returned = true;
                Ok(Some(PacketData::owned(vec![1, 2, 3])))
            } else {
                Ok(None)
            }
        }
    }

    #[test]
    fn test_packet_source_defaults_and_box() {
        let mut source: Box<dyn PacketSource> = Box::new(MinimalSource { returned: false });
        assert_eq!(source.datalink(), Datalink::Raw);
        assert_eq!(source.stats(), None);

        let p1 = source.next_packet().unwrap();
        assert_eq!(p1, Some(PacketData::owned(vec![1, 2, 3])));
        let p2 = source.next_packet().unwrap();
        assert_eq!(p2, None);
    }
}
