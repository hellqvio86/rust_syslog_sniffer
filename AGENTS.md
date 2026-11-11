# AGENTS.md

Guidance and repository conventions for autonomous AI agents and coding assistants working on `rust_syslog_sniffer`.

---

## 1. Project Overview & Architecture

`rust_syslog_sniffer` is a high-performance, low-latency UDP syslog capture and aggregation tool written in pure safe Rust. It captures network datagrams (live via libpcap or replay via PCAP files), parses syslog formats (RFC 3164, RFC 5424, RFC 3339), maintains bounded-memory aggregate statistics, and outputs structured JSON or NDJSON summaries.

### Core Modules (`src/`)

- [`src/lib.rs`](file:///home/hellqvio/git/rust_syslog_sniffer/src/lib.rs): Library entry point, crate-level attributes, and public module exports.
- [`src/app.rs`](file:///home/hellqvio/git/rust_syslog_sniffer/src/app.rs): Core application runtime and capture loop (`run_sniffer`), signal handling (`ctrlc`), interval timers, output emission, and `RunOptions` decoupling.
- [`src/capture.rs`](file:///home/hellqvio/git/rust_syslog_sniffer/src/capture.rs): Packet source abstraction (`PacketSource` trait) with `LiveCapture` (Linux/Unix raw sockets via libpcap) and `FileCapture` (offline `.pcap` replay).
- [`src/decode.rs`](file:///home/hellqvio/git/rust_syslog_sniffer/src/decode.rs): Zero-copy link-layer and UDP/IP decoders for Ethernet, 802.1Q/802.1ad VLAN tags, Linux SLL/SLL2 (Cooked), BSD Loopback/Null, and Raw IP.
- [`src/parser.rs`](file:///home/hellqvio/git/rust_syslog_sniffer/src/parser.rs): Fast, allocation-efficient syslog parser supporting RFC 3164 (BSD syslog), RFC 5424 (IETF syslog with `-` NILVALUE), and RFC 3339 timestamps without version prefix.
- [`src/stats.rs`](file:///home/hellqvio/git/rust_syslog_sniffer/src/stats.rs): Bounded-memory statistics tracker (`StatsTracker`, `SummaryReport`, `HostStats`), sender IP tracking, and libpcap kernel drop delta tracking.
- [`src/config.rs`](file:///home/hellqvio/git/rust_syslog_sniffer/src/config.rs): Command-line argument parsing and validation via `clap` (derives and validation rules).
- [`src/main.rs`](file:///home/hellqvio/git/rust_syslog_sniffer/src/main.rs): CLI binary entry point, process logging setup, signal handling, and exit code management.

---

## 2. Invariants & Strict Guardrails

When modifying this repository, AI agents **MUST** respect the following non-negotiable invariants:

1. **Safety Guarantee (`forbid(unsafe_code)`)**:
   - `#![forbid(unsafe_code)]` is strictly enforced in `src/lib.rs` and `src/main.rs`.
   - Never introduce `unsafe` blocks, helper functions, or external crates that require `unsafe` in our code.
2. **Minimum Supported Rust Version (MSRV)**:
   - Declared MSRV is **Rust 1.88.0** (`rust-version = "1.88"` in `Cargo.toml`). Required by dependency baselines (such as `thiserror` 2.0 and cargo lockfile v4).
   - Do not use language or compiler features requiring Rust > 1.88.
   - Always verify MSRV compatibility using `cargo check --locked --all-targets` on Rust 1.88.0 (or `make msrv`).
3. **Bounded Memory Constraints**:
   - In live network monitoring, attacker-controlled traffic must never cause unbounded allocations.
   - Respect `--max-hosts` (default 10,000) and track overflow counters (`distinct_hosts_overflowed`, `packets_from_overflowed_hosts`) rather than unbounded map growth.
   - Respect `--max-sources` (default 10,000) for global independent sender IP tracking (`senders` map and `senders_overflowed`).
   - Keep packet sample storage bounded by `--sample-bytes` (default 256) and obey `--no-sample`.
   - Host source IPs per host are strictly capped at 8 unique addresses with a `sources_truncated` indicator when keying by hostname; per-host sources are omitted when keying by source IP.
4. **Performance & Zero-Copy Discipline**:
   - Hot capture paths must avoid heap allocations where possible (`Cow<'a, [u8]>`, borrowed string slices, and in-place lookups).
   - Throughput benchmark in `tests/throughput_test.rs` targets > 10M messages/sec on synthetic batches.
5. **Process Exit Code Contract**:
   - `0`: Clean exit (capture finished, duration reached, SIGINT/SIGTERM received, or `BrokenPipe` on stdout).
   - `1`: Capture or runtime failure (interface missing, permission denied, corrupted pcap, fatal I/O).
   - `2`: Invalid CLI arguments or configuration validation errors.

---

## 3. Development, Build, & Verification Commands

All agents must verify code quality and tests before finalizing changes.

### Dependency Management & Build
```bash
# Build binary in debug mode (always use --locked)
cargo build --locked

# Build optimized release binary
cargo build --release --locked
```

### Linter & Code Quality
```bash
# Run all quality checks via Makefile
make lint

# Individual checks:
cargo fmt -- --check
cargo clippy --locked --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
```

### Test Suite
```bash
# Run all unit tests, integration tests, proptest property tests, and throughput tests
cargo test --locked

# Run specific integration tests
cargo test --test integration_test --locked
cargo test --test property_tests --locked
cargo test --test throughput_test --locked

# Run root-privileged live capture loopback test (requires sudo and CAP_NET_RAW)
sudo env "PATH=$PATH" "RUSTUP_HOME=${RUSTUP_HOME:-$HOME/.rustup}" "CARGO_HOME=${CARGO_HOME:-$HOME/.cargo}" cargo test --locked -- --ignored
```

### MSRV Check
```bash
# Verify build against declared MSRV (Rust 1.88.0)
cargo +1.88.0 check --locked --all-targets
```

### Docker & E2E Tests
```bash
# Local container build and end-to-end tests
./tests/e2e_docker.sh
./tests/e2e_periodic_docker.sh
```

---

## 4. Git, CI, & Release Conventions

### Conventional Commits
All commits must follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:
- `fix(...)`: Bug fixes (e.g., `fix(parser): ...`, `fix(capture): ...`, `fix(ci): ...`)
- `feat(...)`: New user-facing features or flags
- `chore(...)`: Maintenance, dependency pins, or release version bumps
- `refactor(...)`: Code refactoring without behavior changes
- `test(...)`: Adding or improving tests
- `perf(...)`: Performance optimizations
- `docs(...)`: Documentation updates

### Pre-commit & Pre-push Hooks
- **Pre-commit** (`.githooks/pre-commit`): Runs fast formatting check, `cargo clippy`, and TruffleHog secrets scan on staged diff in < 1s.
- **Pre-push** (`.githooks/pre-push`): Runs `make lint`, full `cargo test --locked`, TruffleHog git secrets scan, and Trivy vulnerability scan.

### CI Pipeline (`.github/workflows/ci.yml`)
- Triggered on push to `main` and on pull requests.
- Jobs:
  - `detect`: Detects version changes in `Cargo.toml` and checks if a release/tag is required.
  - `msrv`: Enforces build compatibility on Rust 1.88.0.
  - `build-and-test`: Formats, lints, runs tests, executes live root loopback test, and runs `cargo audit`.
  - `docker-build-and-test`: Multi-arch Buildx build (`amd64`, `arm64`, `arm/v7`) with QEMU smoke tests and Docker E2E test runs.
  - `build-release-binaries`: Cross-compiles stripped release binaries with embedded auditable metadata and SBOMs (`amd64`, `arm64`, `armhf`).
  - `create-release`: Generates `SHA256SUMS`, SLSA provenance attestations, creates git tag, and drafts GitHub release.
  - `publish-docker`: Triggered only upon release publication (`release: [published]`), pushing multi-platform images to Docker Hub.
