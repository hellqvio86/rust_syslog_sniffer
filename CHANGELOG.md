# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Link-layer decoding (`src/decode.rs`) for Ethernet (including 802.1Q/802.1ad VLAN tags), Linux SLL, Linux SLL2, BSD Loopback/Null, and Raw IP.
- Zero-dependency ASCII syslog parser (`src/parser.rs`) supporting RFC 5424 (including NILVALUE `-`), RFC 3164 (without mistaking tags `su:` or `sshd[123]:` for hostnames), RFC 3339 timestamps without version digit, PRI validation (0..=191), trailing whitespace/null trimming, and lossless UTF-8 conversion.
- Bounded memory controls: `--max-hosts` (default 10,000) with `hosts_overflowed` metric, `--sample-bytes` (default 256), and `--no-sample`.
- Sender IP tracking: `sources` per host (up to 8 IPs) and `sources_truncated` flag.
- Output formatting options: `--format <pretty|ndjson>` and `--emit-empty`.
- Statistical metrics: `packets_seen`, `datagrams_decoded`, `schema_version`, and libpcap kernel stats deltas.
- Offline packet replay via `--read-pcap <path>`.
- Signal handling for SIGINT and SIGTERM to flush the final summary window gracefully before exiting.
- Option `--duration` with `--interval` kept as a deprecated alias; periodic mode with no duration runs indefinitely until signalled.

### Changed
- Replaced `<` heuristic scanning with full datagram decoding.
- Resolved 100% CPU busy-loop on idle capture sockets.
- Hardened Docker runtime images to use runtime libraries (`libpcap0.8t64`) and least privilege (`CAP_NET_RAW`).
- Removed `regex` crate dependency, reducing binary footprint.
- Removed out-of-scope Ansible scheduling playbooks from the repository.

## [0.1.40] - 2026-11-08

### Added
- Multi-arch Docker build pipeline (amd64, arm64, armv7).
- Git pre-commit hooks with Trivy and TruffleHog.
- Initial periodic reporting and unit test suite.
