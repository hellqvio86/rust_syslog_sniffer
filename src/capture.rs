use pcap::{Active, Capture, Device};

pub fn setup_capture(interface: &str, port: usize) -> Capture<Active> {
    let device = Device::list()
        .expect("device lookup failed")
        .into_iter()
        .find(|d| d.name == interface)
        .unwrap_or_else(|| panic!("Device {} not found", interface));

    let mut cap = Capture::from_device(device)
        .expect("Failed to create capture")
        .immediate_mode(true)
        .timeout(1000)
        .open()
        .expect("Failed to open capture");

    let filter = format!("udp port {}", port);
    cap.filter(&filter, true).expect("Failed to set filter");

    match cap.setnonblock() {
        Ok(c) => c,
        Err(e) => panic!("Failed to set non-blocking mode: {:?}", e),
    }
}
