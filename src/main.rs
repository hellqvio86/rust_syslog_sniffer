use clap::Parser;
use pcap::Device;
use syslog_sniffer::parse_syslog_packet;
use log::{info, debug};
use std::env;

// debug run 
// cargo run -- --interface eth0
//
/// Search for a pattern in a file and display the lines that contain it.
#[derive(Parser)]
#[command(name = "syslog_sniffer")]
#[command(bin_name = "syslog_sniffer")]
struct Cli {
    #[arg(short, long, default_value_t=514)]
    port: usize,
    #[arg(short, long)]
    interface: String,
    #[arg(short, long, default_value_t=false)]
    debug: bool,
}

fn main() {
    let args = Cli::parse();

    if args.debug {
        env::set_var("RUST_LOG", "debug");
    } else if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }
    env_logger::init();

    info!("Port to sniff: {:?}", args.port);
    info!("Interface to sniff: {:?}", args.interface);

    let device = Device::list()
        .expect("device lookup failed")
        .into_iter()
        .find(|d| d.name == args.interface)
        .unwrap_or_else(|| panic!("Device {} not found", args.interface));

    let mut cap = pcap::Capture::from_device(device)
        .expect("Failed to create capture")
        .immediate_mode(true)
        .open()
        .expect("Failed to open capture");
    
    // Set filter for UDP and the specified port
    let filter = format!("udp port {}", args.port);
    cap.filter(&filter, true).expect("Failed to set filter");

    info!("Listening on {} for UDP port {}", args.interface, args.port);
    info!("Datalink: {:?}", cap.get_datalink());
    debug!("Starting capture loop");

    while let Ok(packet) = cap.next_packet() {
        debug!("Received packet: len={}", packet.data.len());
        
        // The packet data includes headers (Ethernet, IP, UDP). 
        // We need to extract the payload.
        // For simplicity in this raw sniffer, we might just try to parse the whole packet 
        // or we can try to be smarter. 
        // pcap returns the whole frame.
        // A robust implementation would parse headers. 
        // However, since we are just "sniffing" and looking for strings, 
        // let's try to find the syslog message in the payload.
        // But wait, `parse_syslog_packet` expects the payload.
        
        // Let's just pass the whole data to `parse_syslog_packet` for now, 
        // but realistically we should skip headers. 
        // Ethernet header is 14 bytes. IP header is usually 20. UDP is 8.
        // Total offset ~ 42 bytes.
        // But this varies (VLANs, IPv6, options).
        
        // For this task, let's just print if we find a valid UTF-8 string that looks like syslog 
        // or just print the payload if we can find it.
        
        // To keep it simple and robust enough for a "sniffer":
        // We will just print the packet data if it parses as UTF-8 string.
        // But the headers will be garbage characters.
        
        // Let's try to be slightly smarter: skip 42 bytes?
        // Or better, just print the length and the raw data if it looks like text.
        
        // Heuristic: Syslog messages typically start with '<' (PRI).
        // We'll scan the packet for this character and try to parse from there.
        // This avoids issues with variable header lengths (e.g. loopback vs ethernet).
        
        if let Some(start_index) = packet.data.iter().position(|&b| b == b'<') {
            if let Some(syslog) = parse_syslog_packet(&packet.data[start_index..]) {
                println!("Captured: {}", syslog.message);
            }
        } else {
             // Fallback: try to parse the whole packet if it's valid UTF-8 (unlikely for raw packets but possible)
             if let Some(syslog) = parse_syslog_packet(packet.data) {
                 println!("Captured: {}", syslog.message);
             }
        }
    }
}
