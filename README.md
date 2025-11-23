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

The sniffer requires `sudo` privileges to capture packets.

```bash
# Run with default settings (10s interval, JSON output, quiet)
sudo ./target/debug/syslog_sniffer --interface eth0

# Run with custom interval (e.g., 30 seconds)
sudo ./target/debug/syslog_sniffer --interface eth0 --interval 30

# Run with debug logging enabled (prints to stderr)
sudo ./target/debug/syslog_sniffer --interface eth0 --debug
```

### Output Format

The application outputs a JSON summary to `stdout` after the interval completes.

```json
{
  "interval_seconds": 60,
  "hosts": {
    "mymachine.example.com": {
      "count": 1,
      "sample": "<165>1 2025-11-23T08:00:00.000Z mymachine.example.com ..."
    }
  }
}
```

### Options

- `-i, --interface <INTERFACE>`: Network interface to sniff on (required).
- `-p, --port <PORT>`: UDP port to listen on (default: 514).
- `--interval <SECONDS>`: Duration to run the sniffer in seconds (default: 10).
- `-d, --debug`: Enable debug logging to stderr.

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

