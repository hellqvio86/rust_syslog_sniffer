# rust_syslog_sniffer

A simple command-line tool to sniff syslog packets over UDP.

## Requirements

- Linux
- `libpcap-dev` (or equivalent for your distro)
- Rust toolchain

## Build

```bash
cargo build
```

## Usage

You need to specify the network interface to listen on. You may need root privileges to capture packets.

```bash
# Listen on eth0, default port 514
sudo ./target/debug/syslog_sniffer --interface eth0

# Listen on wlan0, custom port 5140
sudo ./target/debug/syslog_sniffer -i wlan0 -p 5140
```

### Options

- `-i, --interface <INTERFACE>`: Network interface to sniff on (required).
- `-p, --port <PORT>`: UDP port to listen on (default: 514).

## Makefile

A `Makefile` is included for convenience.

```bash
# Build the project
make build

# Run tests
make test

# Run E2E tests
make test_e2e

# Run the sniffer (defaults to eth0 and port 514)
make run

# Run with custom interface and port
make run INTERFACE=wlan0 PORT=5140

# Clean build artifacts
make clean
```

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/hellqvio86/rust_syslog_sniffer/blob/main/LICENSE) file for details.

