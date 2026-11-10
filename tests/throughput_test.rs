use std::io::sink;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Instant;
use syslog_sniffer::app::run_sniffer_with_writer;
use syslog_sniffer::capture::test_helpers::craft_ethernet_ipv4_udp;
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
