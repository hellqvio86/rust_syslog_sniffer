# Rust Syslog Sniffer

[![CI](https://github.com/hellqvio86/rust_syslog_sniffer/actions/workflows/ci.yml/badge.svg)](https://github.com/hellqvio86/rust_syslog_sniffer/actions/workflows/ci.yml)
![Coverage](coverage.svg)
![GitHub Release](https://img.shields.io/github/v/release/hellqvio86/rust_syslog_sniffer)
![Docker Pulls](https://img.shields.io/docker/pulls/hellqvio/syslog_sniffer)
![GitHub Downloads](https://img.shields.io/github/downloads/hellqvio86/rust_syslog_sniffer/total)
![amd64](https://img.shields.io/badge/arch-amd64-blue)
![arm64](https://img.shields.io/badge/arch-arm64-blue)
![armv7](https://img.shields.io/badge/arch-armv7-blue)

Fast, lightweight network packet sniffer for UDP syslog traffic (RFC 3164 and RFC 5424) with JSON summary reports.

## Building and Running

### Local Build

```bash
# Build the project
make build

# Run tests
make test

# Run the application (requires CAP_NET_RAW or root)
make run ARGS="--interface lo --port 514"
```

### Supported Architectures

- **linux/amd64**: Standard 64-bit Intel/AMD systems
- **linux/arm64**: Raspberry Pi 3, 4, 5, and other ARM64 devices
- **linux/arm/v7**: 32-bit Raspberry Pi and other ARMv7 devices

### Docker Build

The project uses Debian Trixie-based multi-architecture Docker images (`linux/amd64`, `linux/arm64`, `linux/arm/v7`) with BuildKit and Buildx.

#### Build Docker Image

```bash
make docker-build
```

Or manually:

```bash
docker build -t syslog_sniffer:latest .
```

#### Run Docker Container

```bash
# Print help
make docker-run

# Run with custom arguments
make docker-run ARGS="--interface eth0 --port 514"

# Run with least privilege (CAP_NET_RAW only, non-root capabilities dropped)
docker run --rm \
  --cap-drop=ALL \
  --cap-add=NET_RAW \
  --security-opt no-new-privileges \
  --network host \
  syslog_sniffer:latest --interface eth0
```

#### Published Docker Images

The image is published on Docker Hub at: [docker.io/hellqvio/syslog_sniffer](https://hub.docker.com/r/hellqvio/syslog_sniffer)

##### Pull Image

```bash
# Pull the latest release
docker pull docker.io/hellqvio/syslog_sniffer:latest

# Or pull a specific version tag
docker pull docker.io/hellqvio/syslog_sniffer:<version>
```

##### Run Published Container

```bash
# Run with least privilege (CAP_NET_RAW only)
docker run --rm --cap-drop=ALL --cap-add=NET_RAW --network host \
  docker.io/hellqvio/syslog_sniffer:latest --interface eth0 --port 514
```

> [!NOTE]
> The container requires only `CAP_NET_RAW` capability for packet capture. Using `--network host` allows the container to access the host's network interfaces. Promiscuous mode (`--promisc`) additionally requires `CAP_NET_ADMIN`.

## Usage

Summary JSON reports are written to **stdout**, while operational and debug logs are written to **stderr**.

```text
syslog_sniffer [OPTIONS]

Options:
  -i, --interface <INTERFACE>   Network interface to sniff on (e.g. eth0, lo) [required unless --read-pcap]
  -p, --port <PORT>             UDP port to sniff (1-65535, default: 514)
  -d, --debug                   Enable debug logging to stderr (logs message content when sampling is enabled)
      --duration <SECS>         Total runtime in seconds (alias: --interval; default: 10s in one-shot mode; 0 or omitted in periodic mode runs indefinitely)
      --periodic                Enable periodic windowed summary output
      --frequency <SECS>        Periodic output interval in seconds (requires --periodic, default: 5)
      --max-hosts <N>           Maximum distinct host entries to track in memory (default: 10000)
      --max-sources <N>         Maximum distinct sender IPs to track in memory (default: 10000)
      --sample-bytes <N>        Maximum sample message bytes to store per host (default: 256; 0 to disable)
      --no-sample               Disable message samples in output (equivalent to --sample-bytes 0)
      --format <pretty|ndjson>  JSON output format: pretty or ndjson (default: pretty)
      --emit-empty              Emit heartbeat summary windows in periodic mode even if no packets were captured (one-shot mode defaults to emitting an empty summary)
      --key-by <hostname|source-ip>
                                Key statistics by claimed hostname or sender source IP (default: hostname)
      --promisc                 Put interface into promiscuous mode (requires CAP_NET_ADMIN)
      --buffer-size <BYTES>     Libpcap kernel buffer size (default: 2097152)
      --snaplen <BYTES>         Packet snaplen (default: 65535)
      --read-pcap <PATH>        Replay packets offline from a .pcap file
  -h, --help                    Print help
  -V, --version                 Print version
```

### Sample Output

```json
{
  "schema_version": 1,
  "interval_seconds": 10,
  "window_duration_seconds": 10.001,
  "window_start": "2026-11-08T04:14:51.669Z",
  "window_end": "2026-11-08T04:15:01.670Z",
  "packets_seen": 42,
  "datagrams_decoded": 42,
  "hosts": {
    "router.example.com": {
      "count": 35,
      "sample": "<134>1 2026-11-08T04:14:52Z router.example.com filterlog - - [fw rule=1] pass in on igb0",
      "sources": [
        "192.168.1.1"
      ]
    },
    "switch.example.com": {
      "count": 7,
      "sample": "<189>Nov 08 04:14:53 switch STP: Port 1 entering forwarding state",
      "sources": [
        "192.168.1.2"
      ]
    }
  },
  "senders": {
    "192.168.1.1": 35,
    "192.168.1.2": 7
  },
  "capture_stats": {
    "received": 42,
    "dropped": 0,
    "if_dropped": 0
  }
}
```

### JSON Schema & Field Reference

All JSON summary reports adhere to `schema_version: 1`:

| Field | Type | Description |
|---|---|---|
| `schema_version` | `u32` | Schema format version (always `1`) |
| `interval_seconds` | `u64` | Configured duration or periodic frequency in seconds |
| `window_duration_seconds` | `f64` | Measured wall-clock duration of the reporting window |
| `window_start` | `string` | Window start timestamp in ISO 8601 UTC format |
| `window_end` | `string` | Window end timestamp in ISO 8601 UTC format |
| `packets_seen` | `u64` | Total raw packets received by the sniffer from libpcap |
| `datagrams_decoded` | `u64` | Total valid UDP datagrams matching destination port |
| `non_matching_port` | `u64` | Captured packets with destination port not matching `--port` (offline replays) *(optional)* |
| `hosts` | `object` | Map of host key (hostname or source IP) to entry statistics |
| `hosts.<host>.count` | `u64` | Number of messages received from this host |
| `hosts.<host>.sample` | `string` | Truncated sample message payload (empty if `--no-sample`) |
| `hosts.<host>.sources` | `array[string]` | Distinct observed sender IP addresses for this host (up to 8) |
| `hosts.<host>.sources_truncated` | `bool` | True if more than 8 distinct sender IPs were seen for this host *(optional)* |
| `senders` | `object` | Independent map of verified sender IP to packet count (up to `--max-sources`) *(optional)* |
| `hosts_overflowed` | `u64` | Deprecated counter for packets dropped after `--max-hosts` reached (mirrors `packets_from_overflowed_hosts`) *(optional)* |
| `packets_from_overflowed_hosts` | `u64` | Total packet count received for hosts that could not be tracked because the host table reached `--max-hosts` *(optional)* |
| `distinct_hosts_overflowed` | `u64` | Cardinality of distinct rejected host identifiers (best-effort, bounded up to 1,000 unique keys) *(optional)* |
| `senders_overflowed` | `u64` | Distinct sender IPs rejected after `--max-sources` reached *(optional)* |
| `decode_truncated` | `u64` | Frames truncated before IP/UDP headers could be decoded *(optional)* |
| `decode_unsupported` | `u64` | Non-UDP frames, unsupported protocols, or non-initial fragments *(optional)* |
| `fragmented_first` | `u64` | Initial IP fragments with UDP headers skipped due to incomplete payload *(optional)* |
| `decode_errors` | `u64` | Deprecated sum of link-layer decode errors (`decode_truncated + decode_unsupported`) *(optional)* |
| `parse_errors` | `u64` | UDP payloads that failed syslog message parsing (empty, whitespace/null only, or panic recovery) *(optional)* |
| `no_hostname` | `u64` | Packets parsed where hostname could not be extracted *(optional)* |
| `non_utf8` | `u64` | Packets containing non-UTF-8 bytes (converted losslessly via `from_utf8_lossy`) *(optional)* |
| `capture_stats` | `object` | Kernel-level capture statistics reported by libpcap *(optional)* |
| `capture_stats.received` | `u32` | Packets received by kernel packet filter (pre-filter count) |
| `capture_stats.dropped` | `u32` | Packets dropped due to buffer exhaustion |
| `capture_stats.if_dropped` | `u32` | Packets dropped by network interface driver |

### Exit Codes

| Code | Meaning | Description |
|---|---|---|
| `0` | Success | Normal termination (duration elapsed, SIGINT/SIGTERM clean exit, or broken pipe on stdout) |
| `1` | Runtime Failure | Capture error (device open error, permission denied, corrupt pcap, persistent IO error) |
| `2` | Usage / Configuration Error | Invalid command line arguments, invalid numeric ranges, or validation failures |

## Limitations

- **UDP Only**: Listens to UDP syslog traffic (RFC 3164 and RFC 5424). TCP/TLS syslog (RFC 5425 / RFC 6587) and RELP are not captured.
- **IP Fragmentation**: IP fragments are not reassembled; first fragments carrying the UDP header are counted under `fragmented_first` and payloads are not parsed. Subsequent non-initial fragments carry no UDP port headers and are counted under `decode_unsupported`.
- **VLAN Tagging**: 802.1Q and 802.1ad QinQ tagged frames are decoded and parsed. VLAN-aware BPF filtering is supported on Ethernet links (`or (vlan and udp dst port N)`); for non-Ethernet links such as Linux cooked mode (`SLL`/`SLL2`) or raw IP, standard BPF applies as libpcap does not support VLAN qualifiers on non-Ethernet link types. Note that without hardware VLAN stripping/offloading on non-Ethernet interfaces, tagged packets might be filtered by BPF unless captured on raw Ethernet.
- **Self-Reported Hostnames & Table Evasion**: Hostnames parsed from syslog payloads are self-reported by clients and can be spoofed. An attacker generating traffic with arbitrary hostnames could attempt to fill the host table up to `--max-hosts` to obscure legitimate systems in the overflow counts. To mitigate this evasion risk:
  - An independent, bounded per-source-IP table (`senders: {ip: count}`) tracks sending hosts up to `--max-sources` (default: 10,000) regardless of `--key-by`.
  - The `sources` array records actual observed IP addresses for each host entry.
  - The JSON summary reports both packet counts (`packets_from_overflowed_hosts`, also mirrored in `hosts_overflowed`) and best-effort unique host counts (`distinct_hosts_overflowed`).
  - To index statistics directly by verified network sender rather than claimed hostnames, use `--key-by source-ip`.
- **Privileges**: Packet capture requires the `CAP_NET_RAW` Linux capability (or running as root).
- **Kernel Capture Stats (`capture_stats.received`)**: Under Linux libpcap, `ps_recv` (`capture_stats.received`) counts packets received by the kernel socket filter *pre-filter*, whereas `packets_seen` counts packets that matched the BPF filter. Consequently, `capture_stats.received` can be larger than `packets_seen` when other traffic is present on the interface.
- **Log Confidentiality**: Message samples can contain sensitive data (usernames, internal IPs). When sampling is enabled, `--debug` also logs message bodies to stderr. Use `--no-sample` or `--sample-bytes 0` when shipping reports or logs to shared sinks; in this mode, `--debug` logs only host, source IP, and length without message content.

## Development

```bash
# Check formatting
make fmt-check

# Run linter
make lint

# Run tests
make test

# Security scans
make secrets
make trivy
```

### Supply Chain Security (SBOM)

This project integrates SBOM (Software Bill of Materials) generation and embedding:
- **Embedded SBOM**: Production binaries are built using `cargo-auditable`, embedding dependency metadata into the executable.
- **CycloneDX SBOM**: Standardized SBOM files in JSON format are generated during CI and published with releases.
- **Local Generation**: Use `make sbom` to generate a local CycloneDX SBOM.

## License

[MIT](LICENSE.md)
