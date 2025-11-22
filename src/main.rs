use clap::Parser;
use pcap::Device;
use syslog_sniffer::parse_syslog_packet;

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
}

fn main() {
    let args = Cli::parse();

    println!("Port to sniff: {:?}", args.port);
    println!("Interface to sniff: {:?}", args.interface);

    let device = Device::list()
        .expect("device lookup failed")
        .into_iter()
        .find(|d| d.name == args.interface)
        .unwrap_or_else(|| panic!("Device {} not found", args.interface));

    let mut cap = device.open().expect("Failed to open device");
    
    // Set filter for UDP and the specified port
    let filter = format!("udp port {}", args.port);
    cap.filter(&filter, true).expect("Failed to set filter");

    println!("Listening on {} for UDP port {}", args.interface, args.port);

    while let Ok(packet) = cap.next_packet() {
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
        
        if let Some(syslog) = parse_syslog_packet(packet.data) {
             // This will include headers as "text" if they happen to be valid UTF-8, 
             // which is messy.
             // But `parse_syslog_packet` is what we have.
             // Let's improve `parse_syslog_packet` later if needed.
             println!("Captured: {}", syslog.message);
        } else {
            // If the whole packet isn't valid UTF-8 (likely due to binary headers),
            // we might want to scan for the syslog message.
            // But for now, let's stick to the plan.
            // Actually, `parse_syslog_packet` taking the whole packet including headers 
            // and expecting it to be UTF-8 is wrong because headers are binary.
            
            // Let's do a quick heuristic: skip headers.
            // 14 (Eth) + 20 (IP) + 8 (UDP) = 42 bytes.
            if packet.data.len() > 42 {
                if let Some(syslog) = parse_syslog_packet(&packet.data[42..]) {
                    println!("Captured: {}", syslog.message);
                }
            }
        }
    }
}
