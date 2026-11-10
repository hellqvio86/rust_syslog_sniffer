use crate::config::KeyBy;
use crate::CaptureStats;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::SystemTime;

pub fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        s
    } else {
        let mut end = max_bytes;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        &s[..end]
    }
}

pub fn format_rfc3339_utc(st: SystemTime) -> String {
    let dur = st.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;

    // Howard Hinnant civil day algorithm
    let z = days as i64 + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64 + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m_month = if mp < 10 { mp + 3 } else { mp - 9 };
    let y_final = if m_month <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y_final, m_month, d, h, m, s, millis
    )
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

fn is_false(v: &bool) -> bool {
    !*v
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct HostStats {
    pub count: u64,
    pub sample: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub sources: Vec<String>,
    #[serde(skip_serializing_if = "is_false", default)]
    pub sources_truncated: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct KernelStats {
    pub received: u32,
    pub dropped: u32,
    pub if_dropped: u32,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct JsonSummary {
    pub schema_version: u32,
    pub interval_seconds: u64,
    pub window_duration_seconds: f64,
    pub window_start: String,
    pub window_end: String,
    pub packets_seen: u64,
    pub datagrams_decoded: u64,
    pub hosts: BTreeMap<String, HostStats>,
    #[serde(skip_serializing_if = "is_zero", default)]
    pub hosts_overflowed: u64,
    #[serde(skip_serializing_if = "is_zero", default)]
    pub packets_from_overflowed_hosts: u64,
    #[serde(skip_serializing_if = "is_zero", default)]
    pub distinct_hosts_overflowed: u64,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub senders: BTreeMap<String, u64>,
    #[serde(skip_serializing_if = "is_zero", default)]
    pub senders_overflowed: u64,
    #[serde(skip_serializing_if = "is_zero", default)]
    pub no_hostname: u64,
    #[serde(skip_serializing_if = "is_zero", default)]
    pub non_utf8: u64,
    #[serde(skip_serializing_if = "is_zero", default)]
    pub decode_errors: u64,
    #[serde(skip_serializing_if = "is_zero", default)]
    pub non_matching_port: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub capture_stats: Option<KernelStats>,
}

#[derive(Clone, Debug)]
struct HostEntry {
    count: u64,
    sample: String,
    sources: Vec<IpAddr>,
    sources_truncated: bool,
}

pub struct StatsTracker {
    max_hosts: usize,
    max_sources: usize,
    sample_bytes: usize,
    key_by: KeyBy,
    stats: BTreeMap<String, HostEntry>,
    senders: BTreeMap<IpAddr, u64>,
    overflowed_hosts_set: std::collections::BTreeSet<String>,
    packets_seen: u64,
    datagrams_decoded: u64,
    hosts_overflowed: u64,
    senders_overflowed: u64,
    no_hostname: u64,
    non_utf8: u64,
    decode_errors: u64,
    non_matching_port: u64,
    capture_stats: Option<KernelStats>,
    last_cumulative_stats: Option<CaptureStats>,
}

impl Default for StatsTracker {
    fn default() -> Self {
        Self::new(10_000, 10_000, 256, KeyBy::Hostname)
    }
}

impl StatsTracker {
    pub fn new(max_hosts: usize, max_sources: usize, sample_bytes: usize, key_by: KeyBy) -> Self {
        Self {
            max_hosts,
            max_sources,
            sample_bytes,
            key_by,
            stats: BTreeMap::new(),
            senders: BTreeMap::new(),
            overflowed_hosts_set: std::collections::BTreeSet::new(),
            packets_seen: 0,
            datagrams_decoded: 0,
            hosts_overflowed: 0,
            senders_overflowed: 0,
            no_hostname: 0,
            non_utf8: 0,
            decode_errors: 0,
            non_matching_port: 0,
            capture_stats: None,
            last_cumulative_stats: None,
        }
    }

    pub fn record_packet_seen(&mut self) {
        self.packets_seen += 1;
    }

    pub fn record_datagram_decoded(&mut self) {
        self.datagrams_decoded += 1;
    }

    pub fn record_decode_error(&mut self) {
        self.decode_errors += 1;
    }

    pub fn record_non_matching_port(&mut self) {
        self.non_matching_port += 1;
    }

    pub fn set_capture_stats(&mut self, stats: Option<CaptureStats>) {
        if let Some(curr) = stats {
            let last = self.last_cumulative_stats.unwrap_or(CaptureStats {
                packets_received: 0,
                packets_dropped: 0,
                packets_if_dropped: 0,
            });

            let delta_recv = curr.packets_received.saturating_sub(last.packets_received);
            let delta_drop = curr.packets_dropped.saturating_sub(last.packets_dropped);
            let delta_ifdrop = curr
                .packets_if_dropped
                .saturating_sub(last.packets_if_dropped);

            self.last_cumulative_stats = Some(curr);
            self.capture_stats = Some(KernelStats {
                received: delta_recv,
                dropped: delta_drop,
                if_dropped: delta_ifdrop,
            });
        }
    }

    pub fn add_entry(
        &mut self,
        hostname: Option<&str>,
        src_ip: IpAddr,
        message: &str,
        is_non_utf8: bool,
    ) {
        if is_non_utf8 {
            self.non_utf8 += 1;
        }

        // Track independent per-source-IP statistics
        if let Some(sc) = self.senders.get_mut(&src_ip) {
            *sc += 1;
        } else if self.senders.len() < self.max_sources {
            self.senders.insert(src_ip, 1);
        } else {
            self.senders_overflowed += 1;
        }

        let key_str: String;
        let host_key: &str = match self.key_by {
            KeyBy::SourceIp => {
                key_str = src_ip.to_string();
                &key_str
            }
            KeyBy::Hostname => match hostname {
                Some(h) if !h.trim().is_empty() => truncate_utf8(h, 255),
                _ => {
                    self.no_hostname += 1;
                    return;
                }
            },
        };

        if let Some(entry) = self.stats.get_mut(host_key) {
            entry.count += 1;
            if entry.sources.contains(&src_ip) {
                // already tracked
            } else if entry.sources.len() < 8 {
                entry.sources.push(src_ip);
            } else {
                entry.sources_truncated = true;
            }
        } else if self.stats.len() < self.max_hosts {
            let sample = if self.sample_bytes > 0 {
                truncate_utf8(message, self.sample_bytes).to_string()
            } else {
                String::new()
            };
            self.stats.insert(
                host_key.to_string(),
                HostEntry {
                    count: 1,
                    sample,
                    sources: vec![src_ip],
                    sources_truncated: false,
                },
            );
        } else {
            self.hosts_overflowed += 1;
            if self.overflowed_hosts_set.len() < 1000 {
                self.overflowed_hosts_set.insert(host_key.to_string());
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.stats.is_empty()
            && self.senders.is_empty()
            && self.packets_seen == 0
            && self.hosts_overflowed == 0
            && self.senders_overflowed == 0
            && self.no_hostname == 0
            && self.non_utf8 == 0
            && self.decode_errors == 0
            && self.non_matching_port == 0
    }

    pub fn clear(&mut self) {
        self.stats.clear();
        self.senders.clear();
        self.overflowed_hosts_set.clear();
        self.packets_seen = 0;
        self.datagrams_decoded = 0;
        self.hosts_overflowed = 0;
        self.senders_overflowed = 0;
        self.no_hostname = 0;
        self.non_utf8 = 0;
        self.decode_errors = 0;
        self.non_matching_port = 0;
        self.capture_stats = None;
    }

    pub fn get_summary(
        &self,
        interval_seconds: u64,
        window_duration_seconds: f64,
        window_start: SystemTime,
        window_end: SystemTime,
    ) -> JsonSummary {
        let mut hosts_map = BTreeMap::new();
        for (hostname, entry) in &self.stats {
            hosts_map.insert(
                hostname.clone(),
                HostStats {
                    count: entry.count,
                    sample: entry.sample.clone(),
                    sources: entry.sources.iter().map(|ip| ip.to_string()).collect(),
                    sources_truncated: entry.sources_truncated,
                },
            );
        }

        let mut senders_map = BTreeMap::new();
        for (ip, count) in &self.senders {
            senders_map.insert(ip.to_string(), *count);
        }

        JsonSummary {
            schema_version: 1,
            interval_seconds,
            window_duration_seconds,
            window_start: format_rfc3339_utc(window_start),
            window_end: format_rfc3339_utc(window_end),
            packets_seen: self.packets_seen,
            datagrams_decoded: self.datagrams_decoded,
            hosts: hosts_map,
            hosts_overflowed: self.hosts_overflowed,
            packets_from_overflowed_hosts: self.hosts_overflowed,
            distinct_hosts_overflowed: self.overflowed_hosts_set.len() as u64,
            senders: senders_map,
            senders_overflowed: self.senders_overflowed,
            no_hostname: self.no_hostname,
            non_utf8: self.non_utf8,
            decode_errors: self.decode_errors,
            non_matching_port: self.non_matching_port,
            capture_stats: self.capture_stats.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn test_format_rfc3339_utc() {
        // 2026-11-08T12:00:00Z = 1794139200 unix seconds
        let time = std::time::UNIX_EPOCH + Duration::from_secs(1794139200);
        let formatted = format_rfc3339_utc(time);
        assert_eq!(formatted, "2026-11-08T12:00:00.000Z");
    }

    #[test]
    fn test_stats_tracker() {
        let mut tracker = StatsTracker::default();
        tracker.record_packet_seen();
        tracker.record_datagram_decoded();
        tracker.add_entry(Some("host1"), ip(10, 0, 0, 1), "msg 1", false);
        tracker.add_entry(Some("host1"), ip(10, 0, 0, 2), "msg 2", false);
        tracker.add_entry(Some("host2"), ip(10, 0, 0, 3), "msg 3", false);

        let now = SystemTime::now();
        let summary = tracker.get_summary(10, 10.0, now, now);
        assert_eq!(summary.schema_version, 1);
        assert_eq!(summary.interval_seconds, 10);
        assert_eq!(summary.packets_seen, 1);
        assert_eq!(summary.datagrams_decoded, 1);
        assert_eq!(summary.hosts.len(), 2);
        assert_eq!(summary.hosts.get("host1").unwrap().count, 2);
        assert_eq!(summary.hosts.get("host1").unwrap().sample, "msg 1");
        assert_eq!(
            summary.hosts.get("host1").unwrap().sources,
            vec!["10.0.0.1", "10.0.0.2"]
        );
        assert!(!summary.hosts.get("host1").unwrap().sources_truncated);
        assert_eq!(summary.hosts.get("host2").unwrap().count, 1);
    }

    #[test]
    fn test_key_by_source_ip() {
        let mut tracker = StatsTracker::new(10_000, 10_000, 256, KeyBy::SourceIp);
        tracker.add_entry(
            Some("ignored_hostname"),
            ip(192, 168, 1, 50),
            "test msg",
            false,
        );
        let now = SystemTime::now();
        let summary = tracker.get_summary(5, 5.0, now, now);
        assert_eq!(summary.hosts.len(), 1);
        assert!(summary.hosts.contains_key("192.168.1.50"));
    }

    #[test]
    fn test_sources_capped_at_eight() {
        let mut tracker = StatsTracker::default();
        for i in 1..=10 {
            tracker.add_entry(Some("host1"), ip(10, 0, 0, i), "msg", false);
        }
        let now = SystemTime::now();
        let summary = tracker.get_summary(5, 5.0, now, now);
        let host1 = summary.hosts.get("host1").unwrap();
        assert_eq!(host1.sources.len(), 8);
        assert!(host1.sources_truncated);
    }

    #[test]
    fn test_stats_tracker_clear() {
        let mut tracker = StatsTracker::default();
        tracker.record_packet_seen();
        tracker.add_entry(Some("host1"), ip(10, 0, 0, 1), "msg 1", false);
        assert!(!tracker.is_empty());
        tracker.clear();
        assert!(tracker.is_empty());
    }

    #[test]
    fn test_bounded_memory_max_hosts_overflow() {
        let mut tracker = StatsTracker::new(2, 10_000, 256, KeyBy::Hostname);
        tracker.add_entry(Some("host1"), ip(10, 0, 0, 1), "msg", false);
        tracker.add_entry(Some("host2"), ip(10, 0, 0, 2), "msg", false);
        tracker.add_entry(Some("host3"), ip(10, 0, 0, 3), "msg", false);

        let now = SystemTime::now();
        let summary = tracker.get_summary(10, 10.0, now, now);
        assert_eq!(summary.hosts.len(), 2);
        assert_eq!(summary.hosts_overflowed, 1);
        assert_eq!(summary.packets_from_overflowed_hosts, 1);
        assert_eq!(summary.distinct_hosts_overflowed, 1);
    }

    #[test]
    fn test_sample_bytes_truncation() {
        let mut tracker = StatsTracker::new(10, 10_000, 5, KeyBy::Hostname);
        tracker.add_entry(Some("host1"), ip(10, 0, 0, 1), "hello world", false);
        let now = SystemTime::now();
        let summary = tracker.get_summary(10, 10.0, now, now);
        assert_eq!(summary.hosts.get("host1").unwrap().sample, "hello");
    }

    #[test]
    fn test_sample_bytes_zero_disables_sample() {
        let mut tracker = StatsTracker::new(10, 10_000, 0, KeyBy::Hostname);
        tracker.add_entry(Some("host1"), ip(10, 0, 0, 1), "hello world", false);
        let now = SystemTime::now();
        let summary = tracker.get_summary(10, 10.0, now, now);
        assert_eq!(summary.hosts.get("host1").unwrap().sample, "");
    }

    #[test]
    fn test_sender_ip_tracking_when_hosts_overflowed() {
        let mut tracker = StatsTracker::new(10_000, 10_000, 256, KeyBy::Hostname);
        let attacker_ip: IpAddr = "192.0.2.1".parse().unwrap();

        // 10,000 spoofed hostnames from attacker_ip fills the host table
        for i in 0..10_000 {
            let host = format!("spoofed-host-{}", i);
            tracker.add_entry(Some(&host), attacker_ip, "msg", false);
        }

        // Another spoofed hostname from attacker_ip overflows the host table
        tracker.add_entry(Some("spoofed-host-overflow"), attacker_ip, "msg", false);
        assert_eq!(tracker.hosts_overflowed, 1);

        // Real host from a distinct IP
        let real_ip: IpAddr = "198.51.100.42".parse().unwrap();
        tracker.add_entry(Some("real-host"), real_ip, "msg", false);

        // Host table was full, so real host overflowed
        assert_eq!(tracker.hosts_overflowed, 2);
        assert!(!tracker.stats.contains_key("real-host"));

        // BUT real IP is tracked in senders!
        let summary = tracker.get_summary(10, 10.0, SystemTime::now(), SystemTime::now());
        assert_eq!(summary.hosts_overflowed, 2);
        assert_eq!(summary.packets_from_overflowed_hosts, 2);
        assert_eq!(summary.distinct_hosts_overflowed, 2);
        assert!(summary.senders.contains_key("198.51.100.42"));
        assert_eq!(summary.senders["198.51.100.42"], 1);
        assert_eq!(summary.senders["192.0.2.1"], 10_001);
    }

    #[test]
    fn test_no_hostname_and_non_utf8() {
        let mut tracker = StatsTracker::default();
        tracker.add_entry(None, ip(10, 0, 0, 1), "no host", true);
        tracker.add_entry(Some("  "), ip(10, 0, 0, 2), "blank host", false);
        tracker.add_entry(Some("valid"), ip(10, 0, 0, 3), "valid", true);

        let now = SystemTime::now();
        let summary = tracker.get_summary(10, 10.0, now, now);
        assert_eq!(summary.no_hostname, 2);
        assert_eq!(summary.non_utf8, 2);
        assert_eq!(summary.hosts.len(), 1);
    }

    #[test]
    fn test_kernel_stats_deltas() {
        let mut tracker = StatsTracker::default();
        tracker.set_capture_stats(Some(CaptureStats {
            packets_received: 100,
            packets_dropped: 5,
            packets_if_dropped: 2,
        }));
        let now = SystemTime::now();
        let summary = tracker.get_summary(10, 10.0, now, now);
        let ks = summary.capture_stats.unwrap();
        assert_eq!(ks.received, 100);
        assert_eq!(ks.dropped, 5);
        assert_eq!(ks.if_dropped, 2);

        // Second window with increased counters
        tracker.set_capture_stats(Some(CaptureStats {
            packets_received: 150,
            packets_dropped: 6,
            packets_if_dropped: 2,
        }));
        let summary2 = tracker.get_summary(10, 10.0, now, now);
        let ks2 = summary2.capture_stats.unwrap();
        assert_eq!(ks2.received, 50);
        assert_eq!(ks2.dropped, 1);
        assert_eq!(ks2.if_dropped, 0);
    }

    #[test]
    fn test_truncate_utf8_multibyte() {
        // "hello🦀world" -> crab is 4 bytes at indices 5..9
        let s = "hello🦀world";
        assert_eq!(truncate_utf8(s, 5), "hello");
        assert_eq!(truncate_utf8(s, 6), "hello");
        assert_eq!(truncate_utf8(s, 7), "hello");
        assert_eq!(truncate_utf8(s, 8), "hello");
        assert_eq!(truncate_utf8(s, 9), "hello🦀");
    }
}
