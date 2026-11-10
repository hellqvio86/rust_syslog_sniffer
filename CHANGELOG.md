# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.42] - 2026-11-10

### Security
- Fix critical panic on slicing non-char boundary in RFC 3164 parser when multibyte UTF-8 characters appear at specific byte offsets following `<PRI>` (P0-1).

### Added
- Independent per-source-IP sender tracking (`senders` map) up to `--max-sources` (default: 10,000) to mitigate hostname spoofing and host table evasion.
- Fine-grained link-layer decode error counters (`decode_truncated`, `decode_unsupported`, `fragmented_first`) and `parse_errors` counter.
- Host table overflow distinction: `distinct_hosts_overflowed` for rejected unique hostnames alongside `packets_from_overflowed_hosts`.
- Continuous fuzzing pipeline and targets for RFC 3164/5424 parser, link-layer decoder, and JSON serialization.
- Property-based tests via `proptest` asserting subslice preservation and lossless serialization roundtrips.
- Root live UDP capture test asserting end-to-end packet capture and parsing on loopback.
- Multi-architecture Buildx Docker pipeline with QEMU smoke tests across `linux/amd64`, `linux/arm64`, and `linux/arm/v7`.
- SLSA provenance attestations and `SHA256SUMS` generation for release assets.

### Changed
- Gated Docker image publication strictly on GitHub Release publication (`release: [published]`).
- BPF filter in offline pcap replay now strictly filters packets matching destination `--port`.
- Application handles broken pipes quietly on stdout and exits 0 instead of terminating abnormally.
- Default log level changed to `Warn` so warnings are visible without `--debug`.
- Application core decoupled from clap configuration using `RunOptions`.
- Enhanced capture performance using zero-copy packet data streaming (`Cow<'a, [u8]>`) and borrowed string lookups, exceeding 10M msgs/sec in benchmark.
- Report windows now derive start time from the previous scheduled deadline to eliminate timing drift.
- One-shot mode defaults to emitting an empty JSON summary when zero matching packets are captured.
- Pinned all GitHub Actions by commit SHA and enforced `--locked` flag on all Cargo invocations.
- Dockerfile updated with BuildKit cache mounts and digest-pinned base images.
- Fast git pre-commit hook scanning staged diffs; full tests and image scans moved to pre-push and CI.

### Fixed
- Fatal offline pcap read errors now exit immediately without retrying.
- Kernel capture statistics calculation uses wrapping arithmetic on 32-bit counter rollover.
- MSRV corrected and enforced at Rust 1.88.0.

## [0.1.41] - 2026-11-08

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
