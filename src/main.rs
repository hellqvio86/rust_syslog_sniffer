use log::error;
use std::env;
use syslog_sniffer::app::run_sniffer;
use syslog_sniffer::capture::setup_capture;
use syslog_sniffer::config::{determine_log_level, Config};

fn main() {
    let args = Config::parse();

    let mut builder = env_logger::Builder::from_default_env();
    let env_rust_log_is_set = env::var("RUST_LOG").is_ok();

    if let Some(level) = determine_log_level(args.debug, env_rust_log_is_set) {
        builder.filter_level(level);
    }
    builder.init();

    match setup_capture(&args.interface, args.port) {
        Ok(cap) => {
            run_sniffer(args, cap);
        }
        Err(e) => {
            error!("Failed to setup capture: {}", e);
            std::process::exit(1);
        }
    }
}
