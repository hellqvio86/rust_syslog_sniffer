# TODO — syslog_sniffer critical review (v0.1.42)

- **Project:** `syslog_sniffer` v0.1.42 (Rust 2021, `pcap` 2.x, Docker multi-arch, GitHub Actions)
- **Scope of this review:** full read of `src/*`, `tests/*`, `fuzz/*`, `Cargo.toml`, Makefile, Dockerfile, CI workflows, AGENTS.md, README, existing in-repo `todo.md`
- **Not executed in this sandbox:** `cargo test` / `clippy` / Docker (sandbox rustc 1.75 cannot parse lockfile version 4; MSRV is 1.88)
- **Prior art:** in-repo `todo.md` is a round-2 review that marks most P0/P1 items `[x]`. This file is a **fresh** prioritised backlog against the **current** code. Do not treat old `[x]` as authority without re-checking the file.

## Rules for the agent

1. Work top-down by priority. One task = one conventional commit (`fix(...)`, `feat(...)`, `refactor(...)`, `test(...)`, `chore(...)`, `docs(...)`).
2. **Do not bump `version` in `Cargo.toml`** unless explicitly instructed — a version bump on `main` triggers release + Docker publish.
3. After every task: `make lint && make test` must pass. Unit tests must not need root; root-only tests stay behind `#[ignore]`.
4. Do not break CLI flags or JSON schema incompatibly. Additive JSON fields are fine (`schema_version` stays `1`; document in README).
5. Behaviour changes need tests with real assertions on output / counters, not only “doesn’t panic”.
6. Keep `#![forbid(unsafe_code)]` in `lib.rs` and `main.rs`.
7. Prefer the defaults in **Decisions** at the bottom; do not block on questions.

## What is already good (do not regress)

- `#![forbid(unsafe_code)]`, typed `SnifferError` via `thiserror`, `RunOptions` decoupled from clap for the library path.
- Bounds-checked link/IP/UDP decode (Ethernet + multi-VLAN, Linux SLL/SLL2, Raw, BSD Null/Loopback); IPv4/IPv6 UDP.
- BPF: `udp dst port N` and, on Ethernet, `or (vlan and udp dst port N)`; filter applied for both live and offline (`FileCapture`).
- Bounded host map (`--max-hosts`), bounded senders (`--max-sources`), per-host sources capped at 8 with `sources_truncated`, sample truncation, `parse_errors` / decode counters, `catch_unwind` around `parse_syslog_packet`.
- Idle path sleeps 10 ms on `Ok(None)` (no busy-spin); consecutive capture errors rate-limited and capped.
- Deterministic JSON (`BTreeMap`), stdout data / stderr logs, exit codes 0/1/2, SIGINT/SIGTERM flush, broken-pipe → success.
- Release profile: thin LTO, `codegen-units = 1`, strip. CI: MSRV 1.88 job, clippy `-D warnings`, audit, multi-arch Docker, draft release + publish-on-published, cargo-auditable, SBOM.
- Fuzz targets for parse + decode; proptest property tests; integration + throughput tests; AGENTS.md invariants documented.

---

## P0 — correctness / safety (fix before anything else)

- [x] **P0-1 Hostname key lifetime / ownership on non-UTF8 path**
  - **Where:** `parser.rs` `parse_syslog_packet` Err branch builds `Cow::Owned` message but `hostname: Option<&'a str>` from `valid_prefix` of the original byte slice. Callers pass `syslog.hostname` into `stats.add_entry` while the owned message may outlive or not match the borrowed host slice depending on trim.
  - **Risk:** subtle borrow / wrong hostname association under mixed invalid UTF-8; harder to reason about than necessary.
  - **Fix:** make `SyslogPacket` own the hostname when needed (`Option<Cow<'a, str>>`), or always copy hostname into an owned `String` inside `add_entry` before any further use. Prefer `Option<Cow<'a, str>>` for zero-copy on the happy path.
  - **Test:** non-UTF8 payload with a valid PRI + RFC3164-looking ASCII prefix hostname; assert host key and `non_utf8` counter; property test that hostname (if present) is always a substring of the original input bytes’ valid UTF-8 prefix or of the lossy message.

- [x] **P0-2 Per-host `sources` logic is wrong under `KeyBy::SourceIp`**
  - **Where:** `stats.rs` `add_entry` → `HostStorage::SourceIp` branch always pushes `src_ip` into `entry.sources` (the map key *is* the source IP).
  - **Problem:** under source-IP keying, `sources` is redundant and the “8 unique sources” story only makes sense for hostname keying. JSON may show a single-IP list that confuses operators.
  - **Fix:** when `KeyBy::SourceIp`, either omit `sources` / `sources_truncated` from `HostStats` (or always empty / skip serialize) **or** document that under source-IP mode `sources` is unused. Prefer omit via `skip_serializing_if` when empty and never populate in that branch.
  - **Test:** `--key-by source-ip` summary has no misleading multi-source list; hostname mode still caps at 8 and sets `sources_truncated`.

- [x] **P0-3 Overflow counters naming vs semantics**
  - **Where:** `hosts_overflowed` increments once per **packet** after the host map is full; JSON exposes `distinct_hosts_overflowed` and `packets_from_overflowed_hosts` (verify exact field names in `JsonSummary`).
  - **Problem:** operators reading “distinct hosts overflowed” may expect cardinality of rejected host keys, but the primary counter is packet-oriented. The secondary `overflowed` BTreeSet is capped at 1000 and never surfaces clearly.
  - **Fix:** ensure JSON fields match semantics:
    - `packets_from_overflowed_hosts` (or keep current name) = packet count after full table
    - `distinct_hosts_overflowed` = `overflowed.len()` (or running distinct count if set is truncated)
  - Document both in README “Output” section. Add a unit test that fills `max_hosts`, then sends N new hosts and asserts both counters.

- [x] **P0-4 `catch_unwind` only wraps parse, not decode**
  - **Where:** `app.rs` wraps `parse_syslog_packet` only.
  - **Risk:** a future panic in `decode_datagram` still kills the process. Decode is currently panic-free by inspection and fuzz, but defence-in-depth is cheap.
  - **Fix:** wrap `decode_datagram(...)` in `catch_unwind` as well; on panic increment `decode_errors` (or a dedicated `internal_errors` if you want separation) and continue. Do **not** swallow real `SnifferError` from the source.
  - **Test:** inject a mock that panics inside a test-only decode hook, or document that fuzz is the guard and add a comment + CI fuzz job if missing.

---

## P1 — behaviour, API hygiene, observability

- [x] **P1-1 Default log level vs `warn!`**
  - Confirm `env_logger` default in `main.rs` / `init_and_run`. Capture-error `warn!`, deprecation, and signal-handler failures must be visible without `--debug`.
  - **Fix:** default filter `Warn` (or `Info` if you intentionally want more); honour `RUST_LOG`. `--debug` → `Debug`.
  - **Test:** with default logger in a unit test builder, a forced warn path is recorded (or document manual check in TESTING.md).

- [x] **P1-2 `--debug` + `--no-sample` still can log message bodies**
  - **Where:** `app.rs` debug branch: when `sample_bytes > 0` logs truncated body; when `0` logs `len=` only — good. Verify no other `debug!` / `info!` prints raw payload (parser/decode).
  - **Fix:** audit all log lines for payload content; under `--no-sample` never print message text. Optionally redact sample in debug when a future “sensitive” flag appears.
  - **Test:** `--no-sample --debug` path with known payload; assert log sink does not contain the payload string.

- [x] **P1-3 Config validation completeness**
  - `RunOptions::validate` only checks `frequency <= duration` in periodic mode.
  - **Add:** reject `frequency == 0` if not already clamped everywhere; reject `port == 0` if undesired; ensure `max_hosts >= 1`, `max_sources >= 1` (CLI parsers exist — keep library path consistent when constructing `RunOptions` by hand).
  - Validate **before** opening the capture device in `main` / `run_app` so bad CLI fails with exit 2 without requiring CAP_NET_RAW.
  - **Test:** invalid combos via `Config::try_parse_from` and via `RunOptions::validate`.

- [x] **P1-4 Library / binary boundary**
  - `config::Config` is clap-derived and re-exported; fine for a binary crate, but library users pull clap.
  - **Fix (light):** keep `RunOptions` as the public library config; mark clap `Config` as binary-oriented (`pub` only if needed for tests) or feature-gate `cli`. Do not break existing binary.
  - Deprecation of `--interval`: warn only from `main`, not from library code inspecting `env::args()`.

- [x] **P1-5 Error type cleanup**
  - `SnifferError` has overlapping stringly variants: `Capture`, `CaptureClosed`, `PersistentCapture`, `Decode(String)`.
  - **Fix:** prefer structured variants; map `pcap::Error` once; avoid `format!` into `Capture` for config errors (use a `Config(String)` or `thiserror` source). Keep `Display` stable for operators.

- [x] **P1-6 BPF coverage for non-Ethernet VLAN**
  - Ethernet filter includes VLAN; SLL/SLL2/Raw do not.
  - **Fix:** document that VLAN-aware BPF is Ethernet-only, **or** extend filters where libpcap syntax supports it for the active datalink. Add a crafted VLAN pcap test for Ethernet (already partially present) and a doc note for other link types.

- [x] **P1-7 Fragment handling clarity**
  - First fragments counted via `FragmentedFirst`; no reassembly (correct for UDP syslog on purpose).
  - **Fix:** README Limitations: “IP fragments are not reassembled; first fragments are counted under `fragmented_first` and payloads are not parsed.” Add counter to the JSON field table.

---

## P2 — Rust project & code best practices

- [ ] **P2-1 Module size / cohesion**
  - `app.rs` (~960 LOC), `decode.rs` (~900), `stats.rs` (~700) mix production logic and large inline tests.
  - **Fix:** split decode into `decode/link.rs`, `decode/ip.rs` (or `mod` files); move heavy tests to `tests/` or `#[cfg(test)] mod tests` in submodules. Keep public API stable (`decode_datagram`, `Datalink`, `Datagram`).

- [ ] **P2-2 Hot-path allocations**
  - Host keys and samples allocate `String` on first insert; acceptable given bounds, but `truncate_utf8(...).to_string()` runs even when an existing entry only needs `count += 1` (sample already set — OK).
  - **Optional:** store sample only on first insert (already the case); consider `CompactString` / small-string for hostnames if profiling shows pressure. Do not introduce `unsafe`.

- [x] **P2-3 `PacketSource` + lifetimes**
  - `next_packet` returns `PacketData<'_>` tied to the source borrow — good. Ensure no hidden owned copies on the live path (`PacketData::borrowed`).
  - Document that callers must fully process the packet before the next `next_packet` call (classic pcap constraint).

- [x] **P2-4 Clippy / lint policy**
  - `clippy.toml` is present; CI uses `-D warnings`.
  - **Fix:** run `cargo clippy --locked --all-targets -- -D warnings` and clear any residual allows. Prefer fixing over `#[allow]`. Keep `unsafe_code = forbid` in Cargo.toml lints.

- [x] **P2-5 MSRV discipline**
  - Declared `rust-version = "1.88"` — unusually high; CI has an MSRV job (good).
  - **Fix:** document *why* 1.88 in README/AGENTS (language features or dependency floor). Add `make msrv` target wrapping `cargo +1.88 check --locked --all-targets`. Avoid edition-2024 or post-1.88 APIs.

- [x] **P2-6 Dependency hygiene**
  - Locked deps; Renovate present.
  - **Add:** `cargo deny` (licenses + advisories) or document that `cargo audit` in CI is sufficient. Ensure no accidental `default-features` bloat on `clap` / `pcap` if features can be narrowed.

- [x] **P2-7 Test speed & isolation**
  - Prefer pure unit tests for decode/parser/stats; keep one ignored live `lo` test.
  - Property tests and throughput tests should stay under a few seconds on CI; gate heavier benches with `#[ignore]` or a feature.
  - E2E shell scripts: fail on sniffer non-zero exit (`wait` without `|| true` unless intentional); assert final JSON parses.

- [x] **P2-8 Fuzz in CI**
  - `fuzz/` targets exist; workflow `fuzz.yml` present — confirm it runs on a schedule or PR label and uploads crashes. Seed corpus already under `fuzz/corpus/{parse,decode}`.

---

## P3 — project packaging, Docker, CI polish

- [x] **P3-1 Single source of truth for release gating**
  - CI `detect` job already gates release vs Docker publish-on-`release: published`.
  - **Verify** on a dry-run: version bump → draft release + binaries; publishing the GitHub release → Docker Hub push; re-run does not duplicate tags.
  - Document the flow in README “Releasing” or CONTRIBUTING.

- [x] **P3-2 Dockerfile least privilege**
  - Confirm non-root user where possible; runtime still needs `CAP_NET_RAW` (Makefile `docker-run` drops all and adds NET_RAW — good).
  - Multi-stage build, minimal runtime (Debian Trixie-based per README). Pin base image digests if not already.

- [x] **P3-3 `.dockerignore` / context**
  - Already excludes `target/`, `.git`, docs, tests, `*.md`, `.env`. Re-check nothing sensitive is copied; remove stale paths if any.

- [x] **P3-4 Makefile ergonomics**
  - `make lint` = fmt-check + clippy + doc — good.
  - Add `make msrv`, `make fuzz` (document cargo-fuzz install), keep `ARGS=` pattern for run.

- [x] **P3-5 Stale in-repo `todo.md`**
  - Replace the checked-in `todo.md` with this file (or archive old review under `docs/reviews/`) so agents do not follow completed or contradictory items.

---

## P4 — documentation

- [x] **P4-1 README accuracy**
  - CLI flags table matches `Config` (including hidden `--interval`).
  - JSON field table matches `JsonSummary` (including overflow, decode, parse, fragment, non_matching_port, capture_stats).
  - Limitations: UDP only; no fragment reassembly; hostname is self-reported; samples may be sensitive; BPF VLAN note; requires CAP_NET_RAW / root for live capture.
  - Exit codes 0 / 1 / 2.

- [x] **P4-2 AGENTS.md vs code**
  - Align “sources per host capped at 8” with code; clarify `max_sources` = global senders map, not per-host.
  - MSRV 1.88, forbid unsafe, bounded memory — keep as invariants.

- [x] **P4-3 CHANGELOG**
  - Maintain `## [Unreleased]`; record security/behaviour fixes (parser robustness, overflow semantics, log defaults) when shipping.

- [x] **P4-4 TESTING.md / WORKFLOW_SUMMARY**
  - Point at `make test`, ignored root tests, e2e docker scripts, fuzz corpus update instructions.

---

## P5 — backlog (after P0–P2)

- [ ] Facility / severity histograms (PRI already parsed in `extract_hostname`; return `pri` from parser).
- [ ] TCP / TLS syslog (RFC 6587) or hard-document UDP-only.
- [ ] Optional Prometheus metrics endpoint or file sink for long-running periodic mode.
- [ ] “Host went silent” across windows.
- [ ] Optional HashMap host storage behind a flag if deterministic order is not required for a given output mode (pretty JSON can sort on emit).

---

## Decisions (defaults — do not stop to ask)

| Topic | Default |
|---|---|
| Broken pipe | exit 0, quiet |
| Default log level | `Warn`; `--debug` → `Debug`; honour `RUST_LOG` |
| JSON changes | additive only; `schema_version: 1` |
| `--interval` | hidden deprecated; warn in `main`; remove at 0.2.0 |
| MSRV | keep 1.88 until deliberately lowered with CI proof |
| One-shot, no traffic | emit empty summary only if `--emit-empty`; otherwise match current behaviour |
| Panic defence | keep `catch_unwind` on parse; extend to decode (P0-4) |
| Version bump | only on explicit release instruction |
| Sources under `KeyBy::SourceIp` | do not populate / skip serialize (P0-2) |

## Suggested order of work

1. **P0-1, P0-2, P0-3** (data correctness) with tests → patch release when ready.
2. **P0-4, P1-1, P1-2, P1-3** (safety + operator-visible behaviour).
3. **P1-4 … P1-7**, then **P2** (structure, clippy, MSRV, fuzz CI).
4. **P3** pipeline/Docker polish; **P4** docs last so they match shipped behaviour.
5. **P5** only after the above.

## Quick verification commands (agent checklist)

```bash
make lint
make test
cargo test --locked -- --ignored   # needs root / CAP_NET_RAW; optional locally
cargo +1.88 check --locked --all-targets
# optional:
cargo fuzz run parse -- -runs=100000
cargo fuzz run decode -- -runs=100000
./tests/e2e_docker.sh
```
