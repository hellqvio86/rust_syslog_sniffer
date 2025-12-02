use serde::Serialize;
use std::collections::HashMap;

#[derive(Serialize)]
pub struct JsonSummary {
    pub interval_seconds: u64,
    pub hosts: HashMap<String, HostStats>,
}

#[derive(Serialize, Clone)]
pub struct HostStats {
    pub count: u64,
    pub sample: String,
}

pub struct StatsTracker {
    stats: HashMap<String, (u64, String)>,
}

impl Default for StatsTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl StatsTracker {
    pub fn new() -> Self {
        Self {
            stats: HashMap::new(),
        }
    }

    pub fn add_entry(&mut self, hostname: String, message: String) {
        self.stats
            .entry(hostname)
            .and_modify(|(count, _)| *count += 1)
            .or_insert((1, message));
    }

    pub fn is_empty(&self) -> bool {
        self.stats.is_empty()
    }

    pub fn clear(&mut self) {
        self.stats.clear();
    }

    pub fn get_summary(&self, interval_seconds: u64) -> JsonSummary {
        let mut hosts_map = HashMap::new();
        for (hostname, (count, sample)) in &self.stats {
            hosts_map.insert(
                hostname.clone(),
                HostStats {
                    count: *count,
                    sample: sample.clone(),
                },
            );
        }

        JsonSummary {
            interval_seconds,
            hosts: hosts_map,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_tracker() {
        let mut tracker = StatsTracker::new();
        assert!(tracker.is_empty());

        tracker.add_entry("host1".to_string(), "msg1".to_string());
        assert!(!tracker.is_empty());

        tracker.add_entry("host1".to_string(), "msg2".to_string());

        let summary = tracker.get_summary(10);
        assert_eq!(summary.hosts.len(), 1);
        assert_eq!(summary.hosts["host1"].count, 2);
        // Sample should be the first one (or whatever logic, currently first one wins in or_insert,
        // but wait, or_insert only inserts if not present.
        // The current logic in main.rs was:
        // .and_modify(|(count, _)| *count += 1)
        // .or_insert((1, syslog.message.clone()));
        // So the sample is the FIRST message encountered.
        assert_eq!(summary.hosts["host1"].sample, "msg1");
    }
    #[test]
    fn test_stats_tracker_default() {
        let tracker = StatsTracker::default();
        assert!(tracker.is_empty());
    }

    #[test]
    fn test_stats_tracker_clear() {
        let mut tracker = StatsTracker::new();
        tracker.add_entry("host1".to_string(), "msg1".to_string());
        assert!(!tracker.is_empty());
        
        tracker.clear();
        assert!(tracker.is_empty());
        let summary = tracker.get_summary(10);
        assert!(summary.hosts.is_empty());
    }
}
