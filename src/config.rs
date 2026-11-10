use clap::{builder::NonEmptyStringValueParser, Parser, ValueEnum};
use std::path::PathBuf;

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum OutputFormat {
    #[default]
    Pretty,
    Ndjson,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum KeyBy {
    #[default]
    Hostname,
    #[value(name = "source-ip")]
    SourceIp,
}

fn parse_max_hosts(s: &str) -> Result<usize, String> {
    let val: usize = s.parse().map_err(|e| format!("{}", e))?;
    if val < 1 {
        return Err("must be at least 1".to_string());
    }
    Ok(val)
}

/// Fast, lightweight network packet sniffer for UDP syslog traffic.
#[derive(Parser, Debug, Clone)]
#[command(name = "syslog_sniffer")]
#[command(bin_name = "syslog_sniffer")]
#[command(version)]
#[command(about = "Network packet sniffer for UDP syslog traffic with JSON summary reports.")]
pub struct Config {
    #[arg(
        short,
        long,
        default_value_t = 514,
        value_parser = clap::value_parser!(u16).range(1..),
        help = "UDP port to sniff (1-65535, default: 514)"
    )]
    pub port: u16,

    #[arg(
        short,
        long,
        required_unless_present = "read_pcap",
        value_parser = NonEmptyStringValueParser::new(),
        help = "Network interface to sniff on (e.g. eth0, lo)"
    )]
    pub interface: Option<String>,

    #[arg(short, long, default_value_t = false, help = "Enable debug logging")]
    pub debug: bool,

    #[arg(
        long,
        help = "Total runtime in seconds before exiting (default: 10 in one-shot mode; 0 or omitted in periodic mode runs until signalled)"
    )]
    pub duration: Option<u64>,

    #[arg(long, hide = true, conflicts_with = "duration")]
    pub interval: Option<u64>,

    #[arg(long, default_value_t = false, help = "Enable periodic summary output")]
    pub periodic: bool,

    #[arg(
        long,
        default_value_t = 5,
        requires = "periodic",
        value_parser = clap::value_parser!(u64).range(1..),
        help = "Frequency in seconds for periodic output (default: 5)"
    )]
    pub frequency: u64,

    #[arg(
        long,
        default_value_t = 10_000,
        value_parser = parse_max_hosts,
        help = "Maximum number of distinct hosts to track in memory (default: 10000)"
    )]
    pub max_hosts: usize,

    #[arg(
        long,
        default_value_t = 256,
        help = "Maximum sample message bytes to store per host, 0 to disable (default: 256)"
    )]
    pub sample_bytes: usize,

    #[arg(
        long,
        default_value_t = false,
        help = "Disable sample message capture in output (equivalent to --sample-bytes 0)"
    )]
    pub no_sample: bool,

    #[arg(
        long,
        value_enum,
        default_value_t = OutputFormat::Pretty,
        help = "Output JSON format: pretty or ndjson (default: pretty)"
    )]
    pub format: OutputFormat,

    #[arg(
        long,
        default_value_t = false,
        help = "Emit summary windows even if no hosts were observed"
    )]
    pub emit_empty: bool,

    #[arg(
        long,
        value_enum,
        default_value_t = KeyBy::Hostname,
        help = "Key summary statistics by: hostname or source-ip (default: hostname)"
    )]
    pub key_by: KeyBy,

    #[arg(
        long,
        default_value_t = false,
        help = "Put interface into promiscuous mode"
    )]
    pub promisc: bool,

    #[arg(
        long,
        default_value_t = 2 * 1024 * 1024,
        value_parser = clap::value_parser!(u32).range(65536..),
        help = "Libpcap buffer size in bytes (>= 65536, default: 2097152)"
    )]
    pub buffer_size: u32,

    #[arg(
        long,
        default_value_t = 65535,
        value_parser = clap::value_parser!(u32).range(64..=262144),
        help = "Packet capture snaplen in bytes (64..=262144, default: 65535)"
    )]
    pub snaplen: u32,

    #[arg(
        long,
        help = "Read packets from a pcap file instead of a live network interface"
    )]
    pub read_pcap: Option<PathBuf>,
}

impl Config {
    /// Effective total duration in seconds.
    /// In periodic mode with no duration specified, returns None (run indefinitely).
    /// If duration is explicitly 0, returns None (run indefinitely).
    /// In one-shot mode with no duration specified, defaults to 10 seconds.
    pub fn effective_duration_secs(&self) -> Option<u64> {
        let dur = self.duration.or(self.interval);
        match dur {
            Some(0) => None,
            Some(d) => Some(d),
            None => {
                if self.periodic {
                    None
                } else {
                    Some(10)
                }
            }
        }
    }

    /// Effective maximum sample bytes per host.
    pub fn effective_sample_bytes(&self) -> usize {
        if self.no_sample {
            0
        } else {
            self.sample_bytes
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        let dur = self.duration.or(self.interval);
        if let Some(d) = dur {
            if d > 0 && self.periodic && self.frequency > d {
                return Err(format!(
                    "Periodic frequency ({}s) cannot be greater than total duration ({}s)",
                    self.frequency, d
                ));
            }
        }
        Ok(())
    }
}

pub fn determine_log_level(debug: bool, env_rust_log_is_set: bool) -> Option<log::LevelFilter> {
    if debug {
        Some(log::LevelFilter::Debug)
    } else if !env_rust_log_is_set {
        Some(log::LevelFilter::Warn)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let args = vec!["syslog_sniffer", "--interface", "eth0", "--port", "1234"];
        let config = Config::parse_from(args);
        assert_eq!(config.interface.as_deref(), Some("eth0"));
        assert_eq!(config.port, 1234);
        assert!(!config.debug);
        assert_eq!(config.max_hosts, 10_000);
        assert_eq!(config.sample_bytes, 256);
        assert_eq!(config.format, OutputFormat::Pretty);
        assert_eq!(config.key_by, KeyBy::Hostname);
        assert_eq!(config.effective_duration_secs(), Some(10));
    }

    #[test]
    fn test_log_level_debug_flag() {
        assert_eq!(
            determine_log_level(true, false),
            Some(log::LevelFilter::Debug)
        );
        assert_eq!(
            determine_log_level(true, true),
            Some(log::LevelFilter::Debug)
        );
    }

    #[test]
    fn test_log_level_default() {
        assert_eq!(
            determine_log_level(false, false),
            Some(log::LevelFilter::Warn)
        );
    }

    #[test]
    fn test_numeric_arg_validation() {
        assert!(
            Config::try_parse_from(["syslog_sniffer", "-i", "lo", "--max-hosts", "0"]).is_err()
        );
        assert!(Config::try_parse_from(["syslog_sniffer", "-i", "lo", "--max-hosts", "1"]).is_ok());

        assert!(Config::try_parse_from(["syslog_sniffer", "-i", "lo", "--snaplen", "0"]).is_err());
        assert!(Config::try_parse_from(["syslog_sniffer", "-i", "lo", "--snaplen", "63"]).is_err());
        assert!(Config::try_parse_from(["syslog_sniffer", "-i", "lo", "--snaplen", "64"]).is_ok());
        assert!(
            Config::try_parse_from(["syslog_sniffer", "-i", "lo", "--snaplen", "262144"]).is_ok()
        );
        assert!(
            Config::try_parse_from(["syslog_sniffer", "-i", "lo", "--snaplen", "262145"]).is_err()
        );

        assert!(
            Config::try_parse_from(["syslog_sniffer", "-i", "lo", "--buffer-size", "0"]).is_err()
        );
        assert!(
            Config::try_parse_from(["syslog_sniffer", "-i", "lo", "--buffer-size", "65535"])
                .is_err()
        );
        assert!(
            Config::try_parse_from(["syslog_sniffer", "-i", "lo", "--buffer-size", "65536"])
                .is_ok()
        );
    }

    #[test]
    fn test_log_level_env_set() {
        assert_eq!(determine_log_level(false, true), None);
    }

    #[test]
    fn test_default_values() {
        let args = vec!["syslog_sniffer", "--interface", "lo"];
        let config = Config::parse_from(args);
        assert_eq!(config.port, 514);
        assert!(!config.debug);
        assert_eq!(config.effective_duration_secs(), Some(10));
        assert!(!config.periodic);
        assert_eq!(config.frequency, 5);
        assert_eq!(config.max_hosts, 10_000);
        assert_eq!(config.sample_bytes, 256);
        assert_eq!(config.effective_sample_bytes(), 256);
        assert_eq!(config.format, OutputFormat::Pretty);
        assert!(!config.emit_empty);

        let mut zero_duration = config.clone();
        zero_duration.duration = Some(0);
        assert_eq!(zero_duration.effective_duration_secs(), None);
    }

    #[test]
    fn test_parse_all_args() {
        let args = vec![
            "syslog_sniffer",
            "--interface",
            "eth0",
            "--port",
            "5514",
            "--debug",
            "--duration",
            "30",
            "--periodic",
            "--frequency",
            "10",
            "--max-hosts",
            "500",
            "--sample-bytes",
            "128",
            "--format",
            "ndjson",
            "--emit-empty",
            "--key-by",
            "source-ip",
        ];
        let config = Config::parse_from(args);
        assert_eq!(config.interface.as_deref(), Some("eth0"));
        assert_eq!(config.port, 5514);
        assert!(config.debug);
        assert_eq!(config.duration, Some(30));
        assert_eq!(config.effective_duration_secs(), Some(30));
        assert!(config.periodic);
        assert_eq!(config.frequency, 10);
        assert_eq!(config.max_hosts, 500);
        assert_eq!(config.sample_bytes, 128);
        assert_eq!(config.format, OutputFormat::Ndjson);
        assert!(config.emit_empty);
        assert_eq!(config.key_by, KeyBy::SourceIp);
    }

    #[test]
    fn test_interval_deprecated_flag() {
        let args = vec!["syslog_sniffer", "--interface", "lo", "--interval", "15"];
        let config = Config::parse_from(args);
        assert_eq!(config.interval, Some(15));
        assert_eq!(config.effective_duration_secs(), Some(15));

        let conflict = vec![
            "syslog_sniffer",
            "-i",
            "lo",
            "--duration",
            "10",
            "--interval",
            "15",
        ];
        assert!(Config::try_parse_from(conflict).is_err());
    }

    #[test]
    fn test_periodic_indefinite_duration() {
        let args = vec!["syslog_sniffer", "--interface", "lo", "--periodic"];
        let config = Config::parse_from(args);
        assert_eq!(config.duration, None);
        assert_eq!(config.effective_duration_secs(), None);
    }

    #[test]
    fn test_no_sample_flag() {
        let args = vec![
            "syslog_sniffer",
            "--interface",
            "lo",
            "--sample-bytes",
            "128",
            "--no-sample",
        ];
        let config = Config::parse_from(args);
        assert_eq!(config.effective_sample_bytes(), 0);
    }

    #[test]
    fn test_validation() {
        let mut config = Config::parse_from(vec![
            "syslog_sniffer",
            "--interface",
            "lo",
            "--periodic",
            "--frequency",
            "10",
            "--duration",
            "5",
        ]);
        assert!(config.validate().is_err());

        config.duration = Some(20);
        assert!(config.validate().is_ok());
    }
}
