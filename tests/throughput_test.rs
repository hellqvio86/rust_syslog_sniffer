use std::io::sink;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Instant;
use syslog_sniffer::app::run_sniffer_with_writer;
use syslog_sniffer::decode::Datalink;
use syslog_sniffer::error::SnifferError;
use syslog_sniffer::{KeyBy, OutputFormat, PacketData, PacketSource, RunOptions};

struct StreamingSyntheticSource {
    remaining: usize,
    frame: Vec<u8>,
}

impl PacketSource for StreamingSyntheticSource {
    fn next_packet(&mut self) -> Result<Option<PacketData<'_>>, SnifferError> {
        if self.remaining > 0 {
            self.remaining -= 1;
            Ok(Some(PacketData::borrowed(&self.frame)))
        } else {
            Err(SnifferError::CaptureClosed("exhausted".to_string()))
        }
    }

    fn datalink(&self) -> Datalink {
        Datalink::Ethernet
    }
}

fn craft_ethernet_ipv4_udp(dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    pkt.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    pkt.extend_from_slice(&[0x08, 0x00]); // IPv4

    let total_len = (20 + 8 + payload.len()) as u16;
    let mut ip_hdr = vec![
        0x45,
        0x00,
        (total_len >> 8) as u8,
        (total_len & 0xff) as u8,
        0x00,
        0x01,
        0x00,
        0x00,
        64,
        17, // TTL=64, UDP=17
        0x00,
        0x00, // checksum placeholder
        192,
        168,
        1,
        10,
        192,
        168,
        1,
        1,
    ];
    let mut sum: u32 = 0;
    for chunk in ip_hdr.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]);
        sum = sum.wrapping_add(word as u32);
    }
    while (sum >> 16) > 0 {
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

#[test]
fn test_throughput_one_million_synthetic_datagrams() {
    let count = 1_000_000;
    let frame = craft_ethernet_ipv4_udp(514, b"<13>Oct 11 22:14:15 myhost syslog message");

    let source = StreamingSyntheticSource {
        remaining: count,
        frame,
    };

    let options = RunOptions {
        port: 514,
        periodic: false,
        frequency: 10,
        duration: None,
        max_hosts: 10_000,
        max_sources: 10_000,
        sample_bytes: 256,
        format: OutputFormat::Ndjson,
        key_by: KeyBy::Hostname,
        emit_empty: false,
    };

    let mut writer = sink();
    let shutdown = Arc::new(AtomicBool::new(false));

    let start = Instant::now();
    let res = run_sniffer_with_writer(options, source, &mut writer, shutdown);
    let elapsed = start.elapsed();

    assert!(res.is_ok());
    let msgs_per_sec = (count as f64) / elapsed.as_secs_f64();
    println!(
        "Throughput: processed {} datagrams in {:.3}s ({:.0} msgs/s)",
        count,
        elapsed.as_secs_f64(),
        msgs_per_sec
    );
    assert!(
        msgs_per_sec > 100_000.0,
        "Expected > 100k msgs/s, got {:.0}",
        msgs_per_sec
    );
}
