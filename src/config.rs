use clap::Parser;

/// Search for a pattern in a file and display the lines that contain it.
#[derive(Parser, Debug)]
#[command(name = "syslog_sniffer")]
#[command(bin_name = "syslog_sniffer")]
pub struct Config {
    #[arg(short, long, default_value_t = 514)]
    pub port: usize,
    #[arg(short, long)]
    pub interface: String,
    #[arg(short, long, default_value_t = false)]
    pub debug: bool,
    #[arg(long, default_value_t = 10)]
    pub interval: u64,
    #[arg(long, default_value_t = false)]
    pub periodic: bool,
    #[arg(long, default_value_t = 5)]
    pub frequency: u64,
}

impl Config {
    pub fn parse() -> Self {
        <Self as clap::Parser>::parse()
    }
}

// Revised helper to match main.rs logic exactly:
// Logic:
// 1. If debug flag is true -> Debug
// 2. If RUST_LOG is NOT set -> Error
// 3. If RUST_LOG IS set -> Don't override (use what's in env)
pub fn determine_log_level(debug: bool, env_rust_log_is_set: bool) -> Option<log::LevelFilter> {
    if debug {
        Some(log::LevelFilter::Debug)
    } else if !env_rust_log_is_set {
        Some(log::LevelFilter::Error)
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
        assert_eq!(config.interface, "eth0");
        assert_eq!(config.port, 1234);
        assert_eq!(config.debug, false);
    }

    #[test]
    fn test_log_level_debug_flag() {
        // Debug flag true -> Debug
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
        // Debug false, Env not set -> Error
        assert_eq!(
            determine_log_level(false, false),
            Some(log::LevelFilter::Error)
        );
    }

    #[test]
    fn test_log_level_env_set() {
        // Debug false, Env set -> None (let env_logger handle it)
        assert_eq!(determine_log_level(false, true), None);
    }

    #[test]
    fn test_default_values() {
        // Only interface is required
        let args = vec!["syslog_sniffer", "--interface", "eth0"];
        let config = Config::parse_from(args);

        assert_eq!(config.interface, "eth0");
        assert_eq!(config.port, 514); // Default port
        assert_eq!(config.debug, false); // Default debug
        assert_eq!(config.interval, 10); // Default interval
        assert_eq!(config.periodic, false); // Default periodic
        assert_eq!(config.frequency, 5); // Default frequency
    }

    #[test]
    fn test_parse_all_args() {
        let args = vec![
            "syslog_sniffer",
            "--interface",
            "eth0",
            "--port",
            "1024",
            "--debug",
            "--interval",
            "20",
            "--periodic",
            "--frequency",
            "15",
        ];
        let config = Config::parse_from(args);

        assert_eq!(config.interface, "eth0");
        assert_eq!(config.port, 1024);
        assert_eq!(config.debug, true);
        assert_eq!(config.interval, 20);
        assert_eq!(config.periodic, true);
        assert_eq!(config.frequency, 15);
    }
}
