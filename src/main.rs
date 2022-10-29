use clap::Parser;
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
}
