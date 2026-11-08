use crate::decode::Datalink;
use crate::error::SnifferError;
use crate::{CaptureStats, PacketData, PacketSource};
use pcap::{Active, Capture, Device, Offline};
use std::path::Path;

pub struct PcapCapture {
    capture: Capture<Active>,
    datalink: Datalink,
}

impl PcapCapture {
    pub fn new(
        interface: &str,
        port: u16,
        promisc: bool,
        snaplen: i32,
        buffer_size: i32,
    ) -> Result<Self, SnifferError> {
        let devices =
            Device::list().map_err(|e| SnifferError::DeviceLookupFailed(e.to_string()))?;
        let device = devices
            .into_iter()
            .find(|d| d.name == interface)
            .ok_or_else(|| SnifferError::DeviceNotFound(interface.to_string()))?;

        let mut cap = Capture::from_device(device)
            .map_err(SnifferError::Pcap)?
            .promisc(promisc)
            .snaplen(snaplen)
            .buffer_size(buffer_size)
            .immediate_mode(true)
            .timeout(250) // 250ms read timeout
            .open()
            .map_err(|e| {
                let msg = e.to_string();
                if msg.to_lowercase().contains("permission")
                    || msg.to_lowercase().contains("operation not permitted")
                {
                    SnifferError::PermissionDenied(format!("{} (needs CAP_NET_RAW or root)", msg))
                } else {
                    SnifferError::Pcap(e)
                }
            })?;

        let filter = format!("udp dst port {}", port);
        cap.filter(&filter, true).map_err(SnifferError::Pcap)?;

        let cap = cap.setnonblock().map_err(SnifferError::Pcap)?;

        let linktype_raw = cap.get_datalink().0;
        let datalink = Datalink::from_pcap_linktype(linktype_raw);

        Ok(Self {
            capture: cap,
            datalink,
        })
    }
}

impl PacketSource for PcapCapture {
    fn next_packet(&mut self) -> Result<Option<PacketData>, SnifferError> {
        match self.capture.next_packet() {
            Ok(packet) => Ok(Some(PacketData {
                data: packet.data.to_vec(),
            })),
            Err(pcap::Error::TimeoutExpired) => Ok(None),
            Err(e) => Err(SnifferError::Pcap(e)),
        }
    }

    fn datalink(&self) -> Datalink {
        self.datalink
    }

    fn stats(&mut self) -> Option<CaptureStats> {
        self.capture.stats().ok().map(|s| CaptureStats {
            packets_received: s.received,
            packets_dropped: s.dropped,
            packets_if_dropped: s.if_dropped,
        })
    }
}

pub struct FileCapture {
    capture: Capture<Offline>,
    datalink: Datalink,
}

impl FileCapture {
    pub fn new(path: &Path) -> Result<Self, SnifferError> {
        let cap = Capture::from_file(path).map_err(SnifferError::Pcap)?;
        let linktype_raw = cap.get_datalink().0;
        let datalink = Datalink::from_pcap_linktype(linktype_raw);
        Ok(Self {
            capture: cap,
            datalink,
        })
    }
}

impl PacketSource for FileCapture {
    fn next_packet(&mut self) -> Result<Option<PacketData>, SnifferError> {
        match self.capture.next_packet() {
            Ok(packet) => Ok(Some(PacketData {
                data: packet.data.to_vec(),
            })),
            Err(pcap::Error::NoMorePackets) => {
                Err(SnifferError::CaptureClosed("End of pcap file".to_string()))
            }
            Err(e) => Err(SnifferError::Pcap(e)),
        }
    }

    fn datalink(&self) -> Datalink {
        self.datalink
    }
}

pub fn setup_capture(interface: &str, port: u16) -> Result<PcapCapture, SnifferError> {
    PcapCapture::new(interface, port, false, 65535, 2 * 1024 * 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capture_invalid_interface() {
        let result = setup_capture("non_existent_interface_xyz", 514);
        assert!(result.is_err());
        let err = result.err().unwrap().to_string();
        assert!(err.contains("non_existent_interface_xyz") || err.contains("Device lookup failed"));
    }

    #[test]
    fn test_file_capture_invalid_file() {
        let result = FileCapture::new(Path::new("/non/existent/file.pcap"));
        assert!(result.is_err());
    }

    #[test]
    #[ignore = "requires root / capture privileges"]
    fn test_capture_lo() {
        let result = setup_capture("lo", 514);
        if let Ok(mut cap) = result {
            let _ = cap.datalink();
            let _ = cap.next_packet();
        }
    }
}
