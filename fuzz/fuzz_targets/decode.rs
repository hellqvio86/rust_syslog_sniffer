#![no_main]
use libfuzzer_sys::fuzz_target;
use syslog_sniffer::decode::{decode_datagram, Datalink};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let (datalink_byte, frame) = data.split_first().unwrap();
    let datalink = match datalink_byte % 6 {
        0 => Datalink::Ethernet,
        1 => Datalink::LinuxSll,
        2 => Datalink::LinuxSll2,
        3 => Datalink::Raw,
        4 => Datalink::NullLoop,
        _ => Datalink::Unsupported(999),
    };
    if let Ok(datagram) = decode_datagram(datalink, frame) {
        let frame_start = frame.as_ptr() as usize;
        let frame_end = frame_start + frame.len();
        let payload_start = datagram.payload.as_ptr() as usize;
        let payload_end = payload_start + datagram.payload.len();
        if !datagram.payload.is_empty() {
            assert!(payload_start >= frame_start);
            assert!(payload_end <= frame_end);
        }
    }
});
