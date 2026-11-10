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
