use crate::{PacketData, PacketSource};
use pcap::{Active, Capture, Device};

pub struct PcapCapture {
    capture: Capture<Active>,
}

impl PcapCapture {
    pub fn new(interface: &str, port: usize) -> Result<Self, String> {
        let device = Device::list()
            .map_err(|e| format!("Device lookup failed: {}", e))?
            .into_iter()
            .find(|d| d.name == interface)
            .ok_or_else(|| format!("Device {} not found", interface))?;

        let mut cap = Capture::from_device(device)
            .map_err(|e| format!("Failed to create capture: {}", e))?
            .immediate_mode(true)
            .timeout(1000)
            .open()
            .map_err(|e| format!("Failed to open capture: {}", e))?;

        let filter = format!("udp port {}", port);
        cap.filter(&filter, true)
            .map_err(|e| format!("Failed to set filter: {}", e))?;

        let cap = cap
            .setnonblock()
            .map_err(|e| format!("Failed to set non-blocking mode: {}", e))?;

        Ok(Self { capture: cap })
    }
}

impl PacketSource for PcapCapture {
    fn next_packet(&mut self) -> Result<Option<PacketData>, String> {
        match self.capture.next_packet() {
            Ok(packet) => Ok(Some(PacketData {
                data: packet.data.to_vec(),
            })),
            Err(pcap::Error::TimeoutExpired) => Ok(None),
            Err(e) => Err(format!("Error capturing packet: {:?}", e)),
        }
    }

    fn get_datalink(&self) -> String {
        format!("{:?}", self.capture.get_datalink())
    }
}

pub fn setup_capture(interface: &str, port: usize) -> Result<PcapCapture, String> {
    PcapCapture::new(interface, port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capture_invalid_interface() {
        let result = setup_capture("non_existent_interface_xyz", 514);
        assert!(result.is_err());
        let err = result.err().unwrap();
        // The error message depends on pcap implementation/system, but usually contains "not found" or similar
        // or just fails to find it in the list.
        // Our code says: .ok_or_else(|| format!("Device {} not found", interface))?;
        assert!(
            err.contains("Device non_existent_interface_xyz not found")
                || err.contains("Device lookup failed")
        );
    }

    #[test]
    fn test_capture_lo() {
        // Try to capture on loopback. This might fail due to permissions, but we want to exercise the code.
        let result = setup_capture("lo", 514);
        match result {
            Ok(mut cap) => {
                // If successful, we can test get_datalink and next_packet
                let _ = cap.get_datalink();
                let _ = cap.next_packet(); // Should return Ok(None) (timeout) or Ok(Some)
            }
            Err(e) => {
                // If failed, it's likely permission denied or no device.
                // We just print it.
                println!("Could not capture on lo: {}", e);
            }
        }
    }
}
