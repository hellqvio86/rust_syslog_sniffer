use crate::decode::Datalink;
use crate::error::SnifferError;
use crate::{CaptureStats, PacketData, PacketSource};
use pcap::{Active, Capture, Device, Offline};
use std::path::Path;

pub fn bpf_filter(port: u16, datalink: Datalink) -> String {
    if datalink == Datalink::Ethernet {
        format!("udp dst port {0} or (vlan and udp dst port {0})", port)
    } else {
        format!("udp dst port {}", port)
    }
}

pub struct PcapCapture {
    capture: Capture<Active>,
    datalink: Datalink,
}

impl PcapCapture {
    pub fn new(
        interface: &str,
        port: u16,
        promisc: bool,
        snaplen: u32,
        buffer_size: u32,
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
            .snaplen(snaplen as i32)
            .buffer_size(buffer_size as i32)
            .immediate_mode(true)
            .timeout(250) // 250ms read timeout
            .open()
            .map_err(|e| {
                let msg = e.to_string();
                if msg.to_lowercase().contains("permission")
                    || msg.to_lowercase().contains("operation not permitted")
                    || msg.contains("CAP_NET_RAW")
                {
                    SnifferError::PermissionDenied(format!("{} (needs CAP_NET_RAW or root)", msg))
                } else {
                    SnifferError::Pcap(e)
                }
            })?;

        let linktype_raw = cap.get_datalink().0;
        let datalink = Datalink::from_pcap_linktype(linktype_raw);
        if let Datalink::Unsupported(raw) = datalink {
            return Err(SnifferError::UnsupportedDatalink(raw));
        }

        let filter = bpf_filter(port, datalink);
        cap.filter(&filter, true).map_err(SnifferError::Pcap)?;

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
    pub fn new(path: &Path, port: u16) -> Result<Self, SnifferError> {
        let mut cap = Capture::from_file(path).map_err(SnifferError::Pcap)?;
        let linktype_raw = cap.get_datalink().0;
        let datalink = Datalink::from_pcap_linktype(linktype_raw);
        if let Datalink::Unsupported(raw) = datalink {
            return Err(SnifferError::UnsupportedDatalink(raw));
        }
        let filter = bpf_filter(port, datalink);
        cap.filter(&filter, true).map_err(SnifferError::Pcap)?;
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

#[doc(hidden)]
pub mod test_helpers {
    use std::path::Path;

    pub fn craft_ethernet_ipv4_udp(dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        pkt.extend_from_slice(&[0x08, 0x00]);

        let total_len = (20 + 8 + payload.len()) as u16;
        let mut ip_hdr = vec![
            0x45,
            0x00,
            (total_len >> 8) as u8,
            (total_len & 0xff) as u8,
            0x12,
            0x34,
            0x00,
            0x00,
            64,
            17,
            0x00,
            0x00,
            192,
            168,
            1,
            10,
            192,
            168,
            1,
            20,
        ];
        let mut sum = 0u32;
        for i in (0..ip_hdr.len()).step_by(2) {
            sum += u16::from_be_bytes([ip_hdr[i], ip_hdr[i + 1]]) as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let csum = !(sum as u16);
        ip_hdr[10] = (csum >> 8) as u8;
        ip_hdr[11] = (csum & 0xff) as u8;
        pkt.extend_from_slice(&ip_hdr);

        let udp_len = (8 + payload.len()) as u16;
        pkt.extend_from_slice(&12345u16.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&udp_len.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(payload);
        pkt
    }

    pub fn craft_vlan_ethernet_ipv4_udp(dst_port: u16, vlan_id: u16, payload: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        pkt.extend_from_slice(&[0x81, 0x00]); // 802.1Q
        pkt.extend_from_slice(&vlan_id.to_be_bytes());
        pkt.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4

        let total_len = (20 + 8 + payload.len()) as u16;
        let mut ip_hdr = vec![
            0x45,
            0x00,
            (total_len >> 8) as u8,
            (total_len & 0xff) as u8,
            0x12,
            0x34,
            0x00,
            0x00,
            64,
            17,
            0x00,
            0x00,
            192,
            168,
            1,
            10,
            192,
            168,
            1,
            20,
        ];
        let mut sum = 0u32;
        for i in (0..ip_hdr.len()).step_by(2) {
            sum += u16::from_be_bytes([ip_hdr[i], ip_hdr[i + 1]]) as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let csum = !(sum as u16);
        ip_hdr[10] = (csum >> 8) as u8;
        ip_hdr[11] = (csum & 0xff) as u8;
        pkt.extend_from_slice(&ip_hdr);

        let udp_len = (8 + payload.len()) as u16;
        pkt.extend_from_slice(&12345u16.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&udp_len.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(payload);
        pkt
    }

    pub fn write_test_pcap(path: &Path, linktype: u32, packets: &[&[u8]]) {
        let mut file_bytes = Vec::new();
        file_bytes.extend_from_slice(&0xa1b2c3d4u32.to_ne_bytes());
        file_bytes.extend_from_slice(&2u16.to_ne_bytes());
        file_bytes.extend_from_slice(&4u16.to_ne_bytes());
        file_bytes.extend_from_slice(&0i32.to_ne_bytes());
        file_bytes.extend_from_slice(&0u32.to_ne_bytes());
        file_bytes.extend_from_slice(&65535u32.to_ne_bytes());
        file_bytes.extend_from_slice(&linktype.to_ne_bytes());

        for pkt in packets {
            let len = pkt.len() as u32;
            file_bytes.extend_from_slice(&1700000000u32.to_ne_bytes());
            file_bytes.extend_from_slice(&0u32.to_ne_bytes());
            file_bytes.extend_from_slice(&len.to_ne_bytes());
            file_bytes.extend_from_slice(&len.to_ne_bytes());
            file_bytes.extend_from_slice(pkt);
        }
        std::fs::write(path, file_bytes).expect("write temp pcap");
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::*;
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
        let result = FileCapture::new(Path::new("/non/existent/file.pcap"), 514);
        assert!(result.is_err());
    }

    #[test]
    fn test_file_capture_valid_pcap() {
        let dummy_pkt = craft_ethernet_ipv4_udp(514, b"<13>Oct 11 22:14:15 host test");
        let path = std::env::temp_dir().join(format!("test_pcap_{}.pcap", std::process::id()));
        write_test_pcap(&path, 1, &[&dummy_pkt]);

        let mut file_cap = FileCapture::new(&path, 514).expect("open valid pcap");
        assert_eq!(file_cap.datalink(), Datalink::Ethernet);
        assert_eq!(file_cap.stats(), None);

        let p1 = file_cap.next_packet().expect("read packet 1");
        assert_eq!(p1, Some(PacketData { data: dummy_pkt }));

        let p2 = file_cap.next_packet();
        assert!(matches!(p2, Err(SnifferError::CaptureClosed(_))));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_file_capture_vlan_tagged_packet_matched_by_bpf() {
        let vlan_pkt = craft_vlan_ethernet_ipv4_udp(514, 100, b"<13>Oct 11 22:14:15 vlanhost test");
        let decoy_pkt = craft_vlan_ethernet_ipv4_udp(9999, 100, b"<13>decoy wrong port");
        let path = std::env::temp_dir().join(format!("test_vlan_pcap_{}.pcap", std::process::id()));
        write_test_pcap(&path, 1, &[&vlan_pkt, &decoy_pkt]);

        let mut file_cap = FileCapture::new(&path, 514).expect("open valid vlan pcap");
        assert_eq!(file_cap.datalink(), Datalink::Ethernet);

        let p1 = file_cap.next_packet().expect("read packet 1");
        assert_eq!(
            p1,
            Some(PacketData {
                data: vlan_pkt.clone()
            })
        );

        // Decoy packet with port 9999 should be filtered out by BPF filter
        let p2 = file_cap.next_packet();
        assert!(matches!(p2, Err(SnifferError::CaptureClosed(_))));

        // Verify decoder decodes the VLAN packet correctly
        let decoded =
            crate::decode_datagram(Datalink::Ethernet, &vlan_pkt).expect("decode vlan packet");
        assert_eq!(decoded.dst_port, 514);
        assert_eq!(decoded.payload, b"<13>Oct 11 22:14:15 vlanhost test");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_file_capture_unsupported_datalink() {
        let path =
            std::env::temp_dir().join(format!("test_pcap_unsupported_{}.pcap", std::process::id()));
        write_test_pcap(&path, 105, &[]); // Linktype 105: IEEE 802.11
        let res = FileCapture::new(&path, 514);
        assert!(matches!(res, Err(SnifferError::UnsupportedDatalink(105))));
        let err_msg = res.err().unwrap().to_string();
        assert!(err_msg.contains("105"));
        assert!(err_msg.contains("Ethernet"));
        assert!(err_msg.contains("Linux SLL"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_file_capture_corrupted_packet_header() {
        let mut file_bytes = Vec::new();
        // Global Header (24 bytes)
        file_bytes.extend_from_slice(&0xa1b2c3d4u32.to_ne_bytes());
        file_bytes.extend_from_slice(&2u16.to_ne_bytes());
        file_bytes.extend_from_slice(&4u16.to_ne_bytes());
        file_bytes.extend_from_slice(&0i32.to_ne_bytes());
        file_bytes.extend_from_slice(&0u32.to_ne_bytes());
        file_bytes.extend_from_slice(&65535u32.to_ne_bytes());
        file_bytes.extend_from_slice(&1u32.to_ne_bytes()); // Ethernet = 1

        // Incomplete Packet Header (only 8 bytes instead of 16)
        file_bytes.extend_from_slice(&[0xaa; 8]);

        let path =
            std::env::temp_dir().join(format!("test_pcap_corrupt_{}.pcap", std::process::id()));
        std::fs::write(&path, file_bytes).expect("write temp pcap");

        let mut file_cap = FileCapture::new(&path, 514).expect("open corrupt pcap");
        let res = file_cap.next_packet();
        assert!(matches!(res, Err(SnifferError::Pcap(_))));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_capture_lo_or_permission_denied() {
        let result = setup_capture("lo", 514);
        match result {
            Ok(mut cap) => {
                let _ = cap.datalink();
                let _ = cap.next_packet();
                let _ = cap.stats();
            }
            Err(SnifferError::PermissionDenied(msg)) => {
                assert!(msg.contains("needs CAP_NET_RAW or root"));
            }
            Err(e) => {
                assert!(!e.to_string().is_empty());
            }
        }
    }
}
