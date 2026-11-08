use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Data link layer types supported by the decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Datalink {
    Ethernet,
    NullLoop,
    LinuxSll,
    LinuxSll2,
    Raw,
    Unsupported(i32),
}

impl Datalink {
    pub fn from_pcap_linktype(linktype: i32) -> Self {
        match linktype {
            1 => Datalink::Ethernet,
            0 | 108 => Datalink::NullLoop,
            113 => Datalink::LinuxSll,
            276 => Datalink::LinuxSll2,
            12 | 228 | 229 => Datalink::Raw,
            other => Datalink::Unsupported(other),
        }
    }
}

/// Decoded UDP datagram with IP and port endpoints and trimmed payload.
#[derive(Debug, PartialEq, Eq)]
pub struct Datagram<'a> {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

/// Decodes a raw frame from a given datalink into a UDP datagram.
///
/// Returns `None` if the frame is not a valid UDP datagram, is truncated,
/// is an unsupported protocol or non-first IP fragment, or has an unsupported datalink.
pub fn decode_datagram(datalink: Datalink, frame: &[u8]) -> Option<Datagram<'_>> {
    let (net_protocol, ip_slice) = decode_link_layer(datalink, frame)?;
    decode_ip_layer(net_protocol, ip_slice)
}

fn decode_link_layer(datalink: Datalink, frame: &[u8]) -> Option<(u16, &[u8])> {
    match datalink {
        Datalink::Ethernet => {
            if frame.len() < 14 {
                return None;
            }
            let mut offset = 12;
            let mut ethertype = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
            offset += 2;

            // Handle 802.1Q (0x8100), 802.1ad (0x88A8), or 0x9100 VLAN tags
            while ethertype == 0x8100 || ethertype == 0x88A8 || ethertype == 0x9100 {
                if frame.len() < offset + 4 {
                    return None;
                }
                offset += 2; // skip TCI
                ethertype = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
                offset += 2;
            }

            Some((ethertype, &frame[offset..]))
        }
        Datalink::LinuxSll => {
            // Linux Cooked Capture v1 (16 bytes)
            if frame.len() < 16 {
                return None;
            }
            let protocol = u16::from_be_bytes([frame[14], frame[15]]);
            Some((protocol, &frame[16..]))
        }
        Datalink::LinuxSll2 => {
            // Linux Cooked Capture v2 (20 bytes, protocol at 0..2)
            if frame.len() < 20 {
                return None;
            }
            let protocol = u16::from_be_bytes([frame[0], frame[1]]);
            Some((protocol, &frame[20..]))
        }
        Datalink::NullLoop => {
            // BSD loopback header (4 bytes address family)
            if frame.len() < 4 {
                return None;
            }
            let af_host = u32::from_ne_bytes([frame[0], frame[1], frame[2], frame[3]]);
            let af_be = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);

            let proto = if af_host == 2 || af_be == 2 {
                0x0800 // IPv4
            } else if af_host == 10
                || af_host == 24
                || af_host == 28
                || af_host == 30
                || af_be == 10
                || af_be == 24
                || af_be == 28
                || af_be == 30
            {
                0x86DD // IPv6
            } else {
                // Fallback: check IP version in the first byte of payload
                if frame.len() > 4 {
                    match frame[4] >> 4 {
                        4 => 0x0800,
                        6 => 0x86DD,
                        _ => return None,
                    }
                } else {
                    return None;
                }
            };
            Some((proto, &frame[4..]))
        }
        Datalink::Raw => {
            if frame.is_empty() {
                return None;
            }
            let proto = match frame[0] >> 4 {
                4 => 0x0800,
                6 => 0x86DD,
                _ => return None,
            };
            Some((proto, frame))
        }
        Datalink::Unsupported(_) => None,
    }
}

fn decode_ip_layer(protocol: u16, slice: &[u8]) -> Option<Datagram<'_>> {
    match protocol {
        0x0800 => decode_ipv4(slice),
        0x86DD => decode_ipv6(slice),
        _ => None,
    }
}

fn decode_ipv4(slice: &[u8]) -> Option<Datagram<'_>> {
    if slice.len() < 20 {
        return None;
    }
    if (slice[0] >> 4) != 4 {
        return None;
    }
    let ihl = ((slice[0] & 0x0F) * 4) as usize;
    if ihl < 20 || slice.len() < ihl {
        return None;
    }

    let total_len = u16::from_be_bytes([slice[2], slice[3]]) as usize;
    if total_len < ihl {
        return None;
    }
    let actual_ip_len = std::cmp::min(total_len, slice.len());
    if actual_ip_len < ihl {
        return None;
    }

    // Check fragment offset (drop non-first fragments)
    let frag_field = u16::from_be_bytes([slice[6], slice[7]]);
    let frag_offset = frag_field & 0x1FFF;
    if frag_offset != 0 {
        return None;
    }

    // Protocol check: 17 for UDP
    if slice[9] != 17 {
        return None;
    }

    let src_ip = IpAddr::V4(Ipv4Addr::new(slice[12], slice[13], slice[14], slice[15]));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(slice[16], slice[17], slice[18], slice[19]));

    let udp_slice = &slice[ihl..actual_ip_len];
    decode_udp(src_ip, dst_ip, udp_slice)
}

fn decode_ipv6(slice: &[u8]) -> Option<Datagram<'_>> {
    if slice.len() < 40 {
        return None;
    }
    if (slice[0] >> 4) != 6 {
        return None;
    }

    let payload_len = u16::from_be_bytes([slice[4], slice[5]]) as usize;
    let total_v6_len = std::cmp::min(40 + payload_len, slice.len());
    if total_v6_len < 40 {
        return None;
    }

    let mut next_hdr = slice[6];

    let mut src_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&slice[8..24]);
    let src_ip = IpAddr::V6(Ipv6Addr::from(src_bytes));

    let mut dst_bytes = [0u8; 16];
    dst_bytes.copy_from_slice(&slice[24..40]);
    let dst_ip = IpAddr::V6(Ipv6Addr::from(dst_bytes));

    let mut offset = 40;
    while next_hdr != 17 {
        match next_hdr {
            44 => {
                // Fragment Header (8 bytes)
                if offset + 8 > total_v6_len {
                    return None;
                }
                next_hdr = slice[offset];
                let frag_offset =
                    (u16::from_be_bytes([slice[offset + 2], slice[offset + 3]]) >> 3) & 0x1FFF;
                if frag_offset != 0 {
                    return None;
                }
                offset += 8;
            }
            0 | 43 | 60 => {
                // Hop-by-Hop (0), Routing (43), Destination Options (60)
                if offset + 2 > total_v6_len {
                    return None;
                }
                next_hdr = slice[offset];
                let ext_len = (slice[offset + 1] as usize + 1) * 8;
                if offset + ext_len > total_v6_len {
                    return None;
                }
                offset += ext_len;
            }
            51 => {
                // Authentication Header (AH)
                if offset + 2 > total_v6_len {
                    return None;
                }
                next_hdr = slice[offset];
                let ext_len = (slice[offset + 1] as usize + 2) * 4;
                if offset + ext_len > total_v6_len {
                    return None;
                }
                offset += ext_len;
            }
            _ => return None,
        }
    }

    let udp_slice = &slice[offset..total_v6_len];
    decode_udp(src_ip, dst_ip, udp_slice)
}

fn decode_udp<'a>(src_ip: IpAddr, dst_ip: IpAddr, udp_slice: &'a [u8]) -> Option<Datagram<'a>> {
    if udp_slice.len() < 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([udp_slice[0], udp_slice[1]]);
    let dst_port = u16::from_be_bytes([udp_slice[2], udp_slice[3]]);
    let udp_len = u16::from_be_bytes([udp_slice[4], udp_slice[5]]) as usize;
    if udp_len < 8 {
        return None;
    }
    let payload_len = udp_len - 8;

    // Use UDP length to trim Ethernet padding, but handle truncated captures safely
    let payload = if udp_slice.len() < 8 + payload_len {
        &udp_slice[8..]
    } else {
        &udp_slice[8..8 + payload_len]
    };

    Some(Datagram {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_ipv4_udp_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        let ip_total_len = (20 + 8 + payload.len()) as u16;
        pkt.push(0x45); // Version 4, IHL 5 (20 bytes)
        pkt.push(0x00); // DSCP / ECN
        pkt.extend_from_slice(&ip_total_len.to_be_bytes());
        pkt.extend_from_slice(&[0x12, 0x34]); // Identification
        pkt.extend_from_slice(&[0x00, 0x00]); // Flags / Frag offset
        pkt.push(64); // TTL
        pkt.push(17); // UDP
        pkt.extend_from_slice(&[0x00, 0x00]); // Checksum (ignored)
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);

        // UDP header
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        let udp_len = (8 + payload.len()) as u16;
        pkt.extend_from_slice(&udp_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]); // Checksum

        // Payload
        pkt.extend_from_slice(payload);
        pkt
    }

    fn build_ipv6_udp_packet(
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        let payload_len = (8 + payload.len()) as u16;

        pkt.push(0x60); // Version 6
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // Traffic class & Flow label
        pkt.extend_from_slice(&payload_len.to_be_bytes()); // Payload len
        pkt.push(17); // Next header: UDP
        pkt.push(64); // Hop limit
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);

        // UDP
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&payload_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(payload);
        pkt
    }

    #[test]
    fn test_ethernet_ipv4_udp_with_padding() {
        let payload = b"<165>1 2026-11-08T00:00:00Z myhost app - - - Test message";
        let ip_pkt =
            build_ipv4_udp_packet([192, 168, 1, 10], [192, 168, 1, 1], 45123, 514, payload);

        let mut eth_frame = Vec::new();
        eth_frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst MAC
        eth_frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]); // src MAC
        eth_frame.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4
        eth_frame.extend_from_slice(&ip_pkt);
        // Add 16 bytes of Ethernet padding (e.g. trailing NULs or garbage)
        eth_frame.extend_from_slice(&[0x00; 16]);

        let datagram = decode_datagram(Datalink::Ethernet, &eth_frame).expect("decode failed");
        assert_eq!(datagram.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(datagram.dst_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(datagram.src_port, 45123);
        assert_eq!(datagram.dst_port, 514);
        assert_eq!(datagram.payload, payload);
    }

    #[test]
    fn test_header_containing_bracket_byte() {
        // Test that 0x3C ('<') in IP headers or ports does NOT confuse the decoder
        let payload = b"Plain message without bracket";
        // Choose source port 0x3C00 (15360) and IP ending in 0x3C (60)
        let ip_pkt = build_ipv4_udp_packet([10, 0, 0, 60], [10, 0, 0, 1], 0x3C00, 514, payload);

        let mut eth_frame = Vec::new();
        eth_frame.extend_from_slice(&[0x3C, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst MAC has '<'
        eth_frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);
        eth_frame.extend_from_slice(&[0x08, 0x00]);
        eth_frame.extend_from_slice(&ip_pkt);

        let datagram = decode_datagram(Datalink::Ethernet, &eth_frame).expect("decode failed");
        assert_eq!(datagram.src_port, 0x3C00);
        assert_eq!(datagram.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 60)));
        assert_eq!(datagram.payload, payload);
    }

    #[test]
    fn test_vlan_tagged_frames() {
        let payload = b"<14>Single VLAN message";
        let ip_pkt = build_ipv4_udp_packet([172, 16, 0, 5], [172, 16, 0, 1], 50000, 514, payload);

        // Single 802.1Q VLAN
        let mut vlan_frame = Vec::new();
        vlan_frame.extend_from_slice(&[0x00; 12]);
        vlan_frame.extend_from_slice(&[0x81, 0x00]); // 802.1Q
        vlan_frame.extend_from_slice(&[0x00, 0x64]); // VLAN 100
        vlan_frame.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4
        vlan_frame.extend_from_slice(&ip_pkt);

        let datagram =
            decode_datagram(Datalink::Ethernet, &vlan_frame).expect("vlan decode failed");
        assert_eq!(datagram.payload, payload);

        // QinQ (Double VLAN: 0x88A8 then 0x8100)
        let mut qinq_frame = Vec::new();
        qinq_frame.extend_from_slice(&[0x00; 12]);
        qinq_frame.extend_from_slice(&[0x88, 0xA8]); // 802.1ad
        qinq_frame.extend_from_slice(&[0x00, 0xC8]); // Outer VLAN 200
        qinq_frame.extend_from_slice(&[0x81, 0x00]); // Inner 802.1Q
        qinq_frame.extend_from_slice(&[0x00, 0x64]); // Inner VLAN 100
        qinq_frame.extend_from_slice(&[0x08, 0x00]); // IPv4
        qinq_frame.extend_from_slice(&ip_pkt);

        let datagram2 =
            decode_datagram(Datalink::Ethernet, &qinq_frame).expect("qinq decode failed");
        assert_eq!(datagram2.payload, payload);
    }

    #[test]
    fn test_ipv6_udp() {
        let payload = b"<134>IPv6 syslog message";
        let mut ipv6_pkt = Vec::new();
        let payload_len = (8 + payload.len()) as u16;

        ipv6_pkt.push(0x60); // Version 6
        ipv6_pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // Traffic class & Flow label
        ipv6_pkt.extend_from_slice(&payload_len.to_be_bytes()); // Payload len
        ipv6_pkt.push(17); // Next header: UDP
        ipv6_pkt.push(64); // Hop limit

        let src_v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst_v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        ipv6_pkt.extend_from_slice(&src_v6);
        ipv6_pkt.extend_from_slice(&dst_v6);

        // UDP
        ipv6_pkt.extend_from_slice(&55555u16.to_be_bytes());
        ipv6_pkt.extend_from_slice(&514u16.to_be_bytes());
        ipv6_pkt.extend_from_slice(&payload_len.to_be_bytes());
        ipv6_pkt.extend_from_slice(&[0x00, 0x00]);
        ipv6_pkt.extend_from_slice(payload);

        // Test over Linux SLL
        let mut sll_frame = vec![0u8; 14];
        sll_frame.extend_from_slice(&[0x86, 0xDD]); // Protocol IPv6
        sll_frame.extend_from_slice(&ipv6_pkt);

        let datagram = decode_datagram(Datalink::LinuxSll, &sll_frame).expect("sll ipv6 failed");
        assert_eq!(
            datagram.src_ip,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(datagram.src_port, 55555);
        assert_eq!(datagram.dst_port, 514);
        assert_eq!(datagram.payload, payload);
    }

    #[test]
    fn test_linux_sll2() {
        let payload = b"<13>SLL2 message";
        let ip_pkt = build_ipv4_udp_packet([127, 0, 0, 1], [127, 0, 0, 1], 1234, 514, payload);

        let mut sll2_frame = Vec::new();
        sll2_frame.extend_from_slice(&[0x08, 0x00]); // protocol IPv4 at 0..2
        sll2_frame.extend_from_slice(&[0u8; 18]); // rest of 20-byte header
        sll2_frame.extend_from_slice(&ip_pkt);

        let datagram =
            decode_datagram(Datalink::LinuxSll2, &sll2_frame).expect("sll2 decode failed");
        assert_eq!(datagram.payload, payload);
    }

    #[test]
    fn test_bsd_null_loop() {
        let payload = b"<13>Loopback message";
        let ip_pkt = build_ipv4_udp_packet([127, 0, 0, 1], [127, 0, 0, 1], 1234, 514, payload);

        let mut loop_frame = Vec::new();
        loop_frame.extend_from_slice(&2u32.to_ne_bytes()); // AF_INET
        loop_frame.extend_from_slice(&ip_pkt);

        let datagram =
            decode_datagram(Datalink::NullLoop, &loop_frame).expect("null/loop decode failed");
        assert_eq!(datagram.payload, payload);
    }

    #[test]
    fn test_raw_ip() {
        let payload = b"<13>Raw IP message";
        let ip_pkt = build_ipv4_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 514, payload);

        let datagram = decode_datagram(Datalink::Raw, &ip_pkt).expect("raw ip decode failed");
        assert_eq!(datagram.payload, payload);
    }

    #[test]
    fn test_non_first_fragment_rejected() {
        let payload = b"Fragmented syslog";
        let mut ip_pkt = build_ipv4_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 514, payload);
        // Set fragment offset = 100
        ip_pkt[6] = 0x00;
        ip_pkt[7] = 100;

        assert!(decode_datagram(Datalink::Raw, &ip_pkt).is_none());
    }

    #[test]
    fn test_non_udp_rejected() {
        let mut ip_pkt = build_ipv4_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 514, b"test");
        ip_pkt[9] = 6; // TCP instead of 17 (UDP)

        assert!(decode_datagram(Datalink::Raw, &ip_pkt).is_none());
    }

    #[test]
    fn test_truncated_garbage_frames() {
        assert!(decode_datagram(Datalink::Ethernet, &[]).is_none());
        assert!(decode_datagram(Datalink::Ethernet, &[0x00; 13]).is_none());
        assert!(decode_datagram(Datalink::Ethernet, &[0xFF; 25]).is_none());
        assert!(decode_datagram(Datalink::LinuxSll, &[0x00; 15]).is_none());
        assert!(decode_datagram(Datalink::LinuxSll2, &[0x00; 19]).is_none());
        assert!(decode_datagram(Datalink::NullLoop, &[0x00; 3]).is_none());
        assert!(decode_datagram(Datalink::NullLoop, &[0x99, 0x99, 0x99, 0x99]).is_none());
        assert!(decode_datagram(Datalink::Raw, &[]).is_none());
        assert!(decode_datagram(Datalink::Raw, &[0x10, 0x00]).is_none());
        assert!(decode_datagram(Datalink::Unsupported(999), &[0x00; 50]).is_none());
    }

    #[test]
    fn test_datalink_from_pcap_linktype() {
        assert_eq!(Datalink::from_pcap_linktype(1), Datalink::Ethernet);
        assert_eq!(Datalink::from_pcap_linktype(0), Datalink::NullLoop);
        assert_eq!(Datalink::from_pcap_linktype(108), Datalink::NullLoop);
        assert_eq!(Datalink::from_pcap_linktype(113), Datalink::LinuxSll);
        assert_eq!(Datalink::from_pcap_linktype(276), Datalink::LinuxSll2);
        assert_eq!(Datalink::from_pcap_linktype(12), Datalink::Raw);
        assert_eq!(Datalink::from_pcap_linktype(228), Datalink::Raw);
        assert_eq!(Datalink::from_pcap_linktype(229), Datalink::Raw);
        assert_eq!(
            Datalink::from_pcap_linktype(999),
            Datalink::Unsupported(999)
        );
    }

    #[test]
    fn test_null_loop_ipv6_and_fallback() {
        let payload = b"<14>NullLoop IPv6";
        let v6_pkt = build_ipv6_udp_packet(
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            1234,
            514,
            payload,
        );

        // AF_INET6 host byte order (24 or 28 on BSD)
        let mut frame = Vec::new();
        frame.extend_from_slice(&24u32.to_ne_bytes());
        frame.extend_from_slice(&v6_pkt);
        let res = decode_datagram(Datalink::NullLoop, &frame).expect("af_inet6 null/loop");
        assert_eq!(res.payload, payload);

        // Fallback with non-matching AF but valid IPv4 byte in payload
        let ip_pkt = build_ipv4_udp_packet([127, 0, 0, 1], [127, 0, 0, 1], 1234, 514, payload);
        let mut frame_fallback = Vec::new();
        frame_fallback.extend_from_slice(&999u32.to_ne_bytes());
        frame_fallback.extend_from_slice(&ip_pkt);
        let res_fb = decode_datagram(Datalink::NullLoop, &frame_fallback).expect("fallback ipv4");
        assert_eq!(res_fb.payload, payload);

        // Fallback with valid IPv6 byte in payload
        let mut frame_v6_fb = Vec::new();
        frame_v6_fb.extend_from_slice(&999u32.to_ne_bytes());
        frame_v6_fb.extend_from_slice(&v6_pkt);
        let res_v6_fb =
            decode_datagram(Datalink::NullLoop, &frame_v6_fb).expect("fallback ipv6 null/loop");
        assert_eq!(res_v6_fb.payload, payload);
    }

    #[test]
    fn test_ipv4_decode_edge_cases() {
        // Shorter than 20 bytes
        assert!(decode_datagram(Datalink::Raw, &[0x45; 19]).is_none());

        // Version not 4
        let mut bad_ver = build_ipv4_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 514, b"test");
        bad_ver[0] = 0x55;
        assert!(decode_datagram(Datalink::Raw, &bad_ver).is_none());

        // IHL < 20 (e.g. 0x44 -> IHL=16)
        let mut bad_ihl = bad_ver.clone();
        bad_ihl[0] = 0x44;
        assert!(decode_datagram(Datalink::Raw, &bad_ihl).is_none());

        // total_length < IHL
        let mut bad_tot = bad_ver.clone();
        bad_tot[0] = 0x45;
        bad_tot[2] = 0;
        bad_tot[3] = 10;
        assert!(decode_datagram(Datalink::Raw, &bad_tot).is_none());

        // UDP slice < 8
        let mut truncated_udp = bad_ver.clone();
        truncated_udp[0] = 0x45;
        truncated_udp.truncate(24); // only 4 bytes of UDP
        assert!(decode_datagram(Datalink::Raw, &truncated_udp).is_none());

        // UDP len < 8
        let mut bad_udp_len =
            build_ipv4_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 514, b"msg");
        bad_udp_len[24] = 0;
        bad_udp_len[25] = 4; // UDP len = 4 < 8
        assert!(decode_datagram(Datalink::Raw, &bad_udp_len).is_none());

        // Truncated capture: packet truncated so udp_slice is shorter than udp_len
        let mut trunc_cap = build_ipv4_udp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            514,
            b"long message payload",
        );
        trunc_cap.truncate(30); // truncates payload
        let d = decode_datagram(Datalink::Raw, &trunc_cap).expect("truncated capture handled");
        assert_eq!(d.payload, &trunc_cap[28..]);
    }

    #[test]
    fn test_ipv6_extension_headers() {
        let payload = b"<13>IPv6 with extension headers";
        let src = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

        // 1. Hop-by-Hop (0) + Routing (43) + Destination Options (60)
        let mut pkt = Vec::new();
        // IPv6 Header: ver=6, next_hdr=0 (hop-by-hop)
        pkt.push(0x60);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]);
        let total_ext_and_udp = 8 + 8 + 8 + 8 + payload.len();
        pkt.extend_from_slice(&(total_ext_and_udp as u16).to_be_bytes());
        pkt.push(0); // next_hdr = HopByHop
        pkt.push(64); // hop limit
        pkt.extend_from_slice(&src);
        pkt.extend_from_slice(&dst);

        // Hop-by-Hop: next_hdr=43 (Routing), len=0 (8 bytes)
        pkt.push(43);
        pkt.push(0);
        pkt.extend_from_slice(&[0x00; 6]);

        // Routing: next_hdr=60 (DestOpts), len=0 (8 bytes)
        pkt.push(60);
        pkt.push(0);
        pkt.extend_from_slice(&[0x00; 6]);

        // Destination Options: next_hdr=17 (UDP), len=0 (8 bytes)
        pkt.push(17);
        pkt.push(0);
        pkt.extend_from_slice(&[0x00; 6]);

        // UDP Header
        let udp_len = (8 + payload.len()) as u16;
        pkt.extend_from_slice(&1234u16.to_be_bytes());
        pkt.extend_from_slice(&514u16.to_be_bytes());
        pkt.extend_from_slice(&udp_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(payload);

        let d = decode_datagram(Datalink::Raw, &pkt).expect("ext headers decode");
        assert_eq!(d.payload, payload);

        // 2. Fragment header with offset = 0
        let mut frag_pkt = Vec::new();
        frag_pkt.push(0x60);
        frag_pkt.extend_from_slice(&[0x00, 0x00, 0x00]);
        let frag_total = 8 + 8 + payload.len();
        frag_pkt.extend_from_slice(&(frag_total as u16).to_be_bytes());
        frag_pkt.push(44); // Fragment Header
        frag_pkt.push(64);
        frag_pkt.extend_from_slice(&src);
        frag_pkt.extend_from_slice(&dst);

        // Fragment Header: next_hdr=17, reserved=0, offset=0, ID=123
        frag_pkt.push(17);
        frag_pkt.push(0);
        frag_pkt.extend_from_slice(&[0x00, 0x00]); // offset = 0
        frag_pkt.extend_from_slice(&123u32.to_be_bytes());

        // UDP Header
        frag_pkt.extend_from_slice(&1234u16.to_be_bytes());
        frag_pkt.extend_from_slice(&514u16.to_be_bytes());
        frag_pkt.extend_from_slice(&udp_len.to_be_bytes());
        frag_pkt.extend_from_slice(&[0x00, 0x00]);
        frag_pkt.extend_from_slice(payload);

        let d_frag = decode_datagram(Datalink::Raw, &frag_pkt).expect("frag offset 0 decode");
        assert_eq!(d_frag.payload, payload);

        // Fragment header with offset != 0 (should be rejected)
        let mut frag_bad = frag_pkt.clone();
        frag_bad[42] = 0x08; // frag offset > 0
        assert!(decode_datagram(Datalink::Raw, &frag_bad).is_none());

        // 3. Authentication Header (51)
        let mut ah_pkt = Vec::new();
        ah_pkt.push(0x60);
        ah_pkt.extend_from_slice(&[0x00, 0x00, 0x00]);
        let ah_total = 12 + 8 + payload.len();
        ah_pkt.extend_from_slice(&(ah_total as u16).to_be_bytes());
        ah_pkt.push(51); // AH
        ah_pkt.push(64);
        ah_pkt.extend_from_slice(&src);
        ah_pkt.extend_from_slice(&dst);

        // AH: next_hdr=17, payload_len=1 ((1+2)*4 = 12 bytes)
        ah_pkt.push(17);
        ah_pkt.push(1);
        ah_pkt.extend_from_slice(&[0x00; 10]);

        // UDP Header
        ah_pkt.extend_from_slice(&1234u16.to_be_bytes());
        ah_pkt.extend_from_slice(&514u16.to_be_bytes());
        ah_pkt.extend_from_slice(&udp_len.to_be_bytes());
        ah_pkt.extend_from_slice(&[0x00, 0x00]);
        ah_pkt.extend_from_slice(payload);

        let d_ah = decode_datagram(Datalink::Raw, &ah_pkt).expect("ah decode");
        assert_eq!(d_ah.payload, payload);

        // 4. Unknown next header rejected
        let mut unk_pkt = ah_pkt.clone();
        unk_pkt[6] = 250; // unknown protocol
        assert!(decode_datagram(Datalink::Raw, &unk_pkt).is_none());

        // 5. Truncated extension headers
        // Truncated Fragment header (< 8 bytes)
        let trunc_frag = frag_pkt[..45].to_vec();
        assert!(decode_datagram(Datalink::Raw, &trunc_frag).is_none());

        // Truncated Hop-by-hop (< 2 bytes)
        let trunc_hbh1 = pkt[..41].to_vec();
        assert!(decode_datagram(Datalink::Raw, &trunc_hbh1).is_none());

        // Truncated Hop-by-hop (< ext_len)
        let trunc_hbh2 = pkt[..44].to_vec();
        assert!(decode_datagram(Datalink::Raw, &trunc_hbh2).is_none());

        // Truncated AH (< 2 bytes)
        let trunc_ah1 = ah_pkt[..41].to_vec();
        assert!(decode_datagram(Datalink::Raw, &trunc_ah1).is_none());

        // Truncated AH (< ext_len)
        let trunc_ah2 = ah_pkt[..46].to_vec();
        assert!(decode_datagram(Datalink::Raw, &trunc_ah2).is_none());
    }

    #[test]
    fn test_decode_additional_edge_cases() {
        // Truncated VLAN header (0x8100 with fewer than 4 remaining bytes)
        let trunc_vlan = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x81, 0x00,
            0x01,
        ];
        assert!(decode_datagram(Datalink::Ethernet, &trunc_vlan).is_none());

        // NullLoop fallback with unrecognized IP version
        let null_loop_bad = vec![0x00, 0x00, 0x00, 0x99, 0x30, 0x00];
        assert!(decode_datagram(Datalink::NullLoop, &null_loop_bad).is_none());

        // IPv4 with wrong version nibble
        let bad_v4_ver = vec![0x55; 20];
        assert!(decode_datagram(Datalink::Raw, &bad_v4_ver).is_none());

        // IPv6 < 40 bytes
        let short_v6 = vec![0x60; 30];
        assert!(decode_datagram(Datalink::Raw, &short_v6).is_none());

        // IPv6 with wrong version nibble
        let bad_v6_ver = vec![0x40; 40];
        assert!(decode_datagram(Datalink::Raw, &bad_v6_ver).is_none());
    }
}
