# TODO — syslog_sniffer critical review (round 2)

- **Project:** `syslog_sniffer` v0.1.41 (Rust, libpcap via `pcap` crate, Docker + GitHub Actions release pipeline)
- **Supersedes:** the `todo.md` currently in the repo (round 1, reviewed at v0.1.40). Replace that file with this one. Round-1 items that are still open are carried over and tagged `(carried: P#-#)`.
- **Method:** full read of every source, script, workflow and doc, **plus the crate was built and exercised**:
  - Built and ran `cargo test --locked` (lib: 69 pass; integration: 2 pass) on rustc 1.85.1; built `--release`.
  - Ran the release binary against `lo` and crafted pcap files; 200 000 random inputs fuzzed through the parser and decoder.
  - Items tagged **(verified)** were reproduced. Items tagged `(verify)` rest on reading only and must be confirmed while fixing.
  - **Not run** (tooling unavailable in the review sandbox): `cargo fmt`, `cargo clippy`, `cargo audit/deny`, Trivy, Docker builds, any GitHub Actions run.

## Rules for the agent

1. Work top-down by priority. One task = one commit, conventional-commit style (`fix(...)`, `feat(...)`, `chore(...)`).
2. **Do NOT bump `version` in `Cargo.toml`** unless told to: a new version on `main` tags a release and pushes Docker Hub `latest` (see P1-1).
3. After every task: `make lint && make test` must pass. Unit tests must not need root; root-only tests go behind `#[ignore]`.
4. Don't change CLI flags or JSON output incompatibly. Additive JSON fields are fine (keep `schema_version: 1`, document them in README).
5. Every behaviour change needs a test with a real assertion on output, not just "doesn't panic". Update README when flags or fields change.
6. Keep `#![forbid(unsafe_code)]`.
7. Use the defaults in "Decisions" at the bottom; do not stop to ask.

## What is good (don't regress)

- Round 1 landed well: real Ethernet/VLAN/SLL/IPv4/IPv6/UDP decoding, `udp dst port` BPF, bounded host map, sample truncation, sources per host, ndjson, `--read-pcap`, typed errors, signal handling, `regex` dropped.
- **(verified)** live capture on `lo` works end to end; idle CPU is ~0.5% (0.03 s CPU in 6 s); SIGTERM flushes a final summary and the process exits.
- Decoder is bounds-checked: 0 panics in 200 000 random frames across Ethernet and Raw.
- Output contract is deterministic (`BTreeMap`), data on stdout / logs on stderr, `CaptureClosed` ends offline replay cleanly.
- Supply-chain posture is above average: committed `Cargo.lock`, `cargo-auditable`, SBOMs, TruffleHog/Trivy, CODEOWNERS, Renovate with digest-pinning configured.

---

## P0 — fix first (remote crash / wrong results)

- [x] **P0-1 Remote panic: one UDP packet crashes the sniffer** **(verified)**
  - **Where:** `src/parser.rs:89` — `let month = &rest_trimmed[0..3];` inside `extract_hostname` (RFC 3164 branch).
  - **Problem:** `rest_trimmed` is a `&str` built from `String::from_utf8_lossy`. Slicing a `str` by byte range panics when byte 3 is not a char boundary. Any payload of the form `<PRI>` followed by a multibyte character straddling byte 3, with ≥15 bytes after the `>`, panics. Repro: `parse_syslog_packet("<13>Ö😀xxxxxxxxxxxxx".as_bytes())` panics ("byte index 3 is not a char boundary"). Random fuzz (200 000 inputs, half with a `<13>` prefix): **30 711 panics, all at this line**.
  - **Impact:** an unauthenticated sender (spoofable, same L2 segment or routed) can kill the process with a single datagram. For a blue-team monitoring tool that is a trivial blinding attack; in Docker without a restart policy the sniffer stays dead.
  - **Fix:**
    - Do the month check on bytes: `rest_trimmed.as_bytes().get(0..3)` compared to `b"Jan"`… (store `MONTHS` as `[&[u8]; 12]`), or use `rest_trimmed.get(0..3)` (returns `None` off-boundary).
    - Audit every other index/slice on `&str` in `parser.rs` (`msg[1..close_idx]` is safe because byte 0 is `<` and `close_idx` is a `>` position; keep it that way or switch to `get`).
    - Prefer parsing on `&[u8]` end-to-end (the payload is bytes anyway) and only build a `String` for the sample.
  - **Acceptance:**
    - Regression test: multibyte chars (2-, 3-, 4-byte, and lossy U+FFFD from invalid bytes) placed at every offset 0..=20 after `<13>` never panic and return a sane result.
    - `proptest`/fuzz (see P2-3) with arbitrary bytes: `parse_syslog_packet` and `decode_datagram` never panic.
    - Consider a defensive `std::panic::catch_unwind` around the per-packet path that increments `parse_errors` (P1-9) and continues; do this *in addition to* the fix, not instead.

- [x] **P0-2 `--read-pcap` ignores `--port`** **(verified)**
  - **Where:** `src/capture.rs` (`FileCapture::new` applies no filter), `src/app.rs` (never compares `datagram.dst_port`).
  - **Problem:** with `--read-pcap file.pcap --port 514` a pcap containing a UDP/53 packet with a syslog-looking payload is counted as a syslog host (reproduced: host `dnsdecoy` from port 53 reported alongside `onport`). Offline mode therefore disagrees with live mode and with the documented behaviour of `--port`. Forensic runs over real captures will report every UDP payload that happens to start with `<`.
  - **Fix:** both of:
    - Apply the same BPF filter string to the offline capture (`Capture<Offline>::filter`), sharing one `fn bpf_filter(port) -> String` with the live path.
    - In the app loop, drop (and count as `non_matching_port`, additive field) any datagram whose `dst_port != config.port`. This also guards live captures if the BPF filter is bypassed or mis-compiled.
  - **Acceptance:** test with a pcap holding one packet to 514 and one to 53 → only the 514 host appears; `--port 53` → only the other.

---

## P1 — behaviour, output contract, release pipeline

- [x] **P1-1 Docker publish is skipped after a successful release job** `(verify in a real run)`
  - **Where:** `.github/workflows/ci.yml` (`create-release` → `publish-docker`), `.github/actions/check-version-change/action.yml`.
  - **Problem:** the composite action decides `changed` by asking `git ls-remote --tags origin vX.Y.Z`. `create-release` runs it, then **pushes that tag**. `publish-docker` (`needs: create-release`) runs the same action afterwards, finds the tag it just saw created, sets `changed=false`, and every publish step (`if: steps.version.outputs.changed == 'true'`) is skipped. Net effect: GitHub draft release is created, **no image is pushed**. Re-running the workflow cannot recover because the tag now exists.
  - **Fix:**
    - Compute the decision once in a small `detect` job (`outputs: version, should_release`) and have `create-release` and `publish-docker` consume `needs.detect.outputs.*` instead of re-evaluating.
    - Make each step idempotent independently: tag exists ≠ image exists. Check the image with `docker buildx imagetools inspect docker.io/hellqvio/syslog_sniffer:$VERSION` before pushing; check the release with `gh release view`.
    - Decide the gating (see P3-1): either push after a human publishes the draft (`on: release: types: [published]`) or document that images publish immediately.
  - **Acceptance:** a dry run on a fork (or `act`) with a new version tags, drafts and pushes exactly once; a re-run is a no-op; a re-run after a failed push completes the push.

- [x] **P1-2 Broken pipe does not stop the sniffer** **(verified)**
  - **Where:** `src/app.rs` `write_summary_json`.
  - **Problem:** `BrokenPipe` is swallowed (`return Ok(())`) and the loop keeps running. `syslog_sniffer --periodic --emit-empty --format ndjson | head -n 1` ran the full 8 s until `timeout` killed it; with no `--duration` it would run forever, capturing into a closed pipe.
  - **Fix:** return a distinguishable result (e.g. `SnifferError::OutputClosed`), stop the loop, skip the final summary, and have `main` exit `0` quietly (or 141 if you prefer SIGPIPE semantics; pick 0 per Decisions).
  - **Acceptance:** unit test with a writer that returns `BrokenPipe` in periodic mode with `duration=None` returns promptly; e2e `| head -n1` exits within one `--frequency`.

- [x] **P1-3 Default log level hides every `warn!`** **(verified)**
  - **Where:** `src/config.rs` `determine_log_level` (default `Error`), `src/main.rs`, `src/app.rs`.
  - **Problem:** capture-error warnings (rate-limited, the P0-3 mechanism from round 1), the `--interval` deprecation warning and the "could not register signal handler" warning are all `warn!`, so at the default level they are never printed. Confirmed: `syslog_sniffer -i lo --interval 1` prints nothing.
  - **Fix:** default to `Warn`; `--debug` → `Debug`; honour `RUST_LOG` as today. Update the e2e "quiet" checks (grep for `ERROR|panicked`, allow `WARN` only where expected).
  - **Acceptance:** test (or e2e) that `--interval 1` emits the deprecation line on stderr by default.

- [x] **P1-4 Attacker can hide real hosts by filling the host table; `hosts_overflowed` is mis-named**
  - **Where:** `src/stats.rs` `add_entry`.
  - **Problem:** keys are self-reported hostnames. A sender that spoofs 10 000 distinct hostnames at the start of a window fills the table; every later (real) host is counted only in `hosts_overflowed`, with no per-host or per-source detail. Also, the counter increments **per packet**, not per distinct host, so the name is misleading.
  - **Fix:**
    - Keep an independent, separately capped per-**source-IP** counter (`senders: {ip: count}`, `--max-sources`, default 10 000, plus `senders_overflowed`) regardless of `--key-by`. Source IPs are the harder-to-spoof dimension on a monitored segment.
    - Rename semantics: keep `hosts_overflowed` for compatibility but document it as packets; add `packets_from_overflowed_hosts` (same value) and `distinct_hosts_overflowed` (best effort, e.g. HyperLogLog-free: count distinct up to a small cap, then `>=N`).
    - Document the evasion risk in README "Limitations".
  - **Acceptance:** test: 10 000 spoofed hostnames then one real host from a distinct IP → real source IP present in `senders`.

- [x] **P1-5 Config validation happens after the capture is opened; numeric args under-validated** **(verified)**
  - **Where:** `src/main.rs`, `src/app.rs` (validate inside `run_sniffer_with_writer`), `src/config.rs`.
  - **Problem:** the `frequency > duration` check runs only after the interface is opened (needs root, may fail first for the wrong reason) and surfaces as `Capture("Configuration error: …")`. `--max-hosts 0`, `--snaplen=0`, `--buffer-size=-5` are all accepted (exit 0). `buffer_size`/`snaplen` are `i32`.
  - **Fix:** validate in `main` before touching pcap (exit code 2, clap-style message) or encode in clap (`value_parser` ranges, `ArgGroup`/custom validator). Use `u32` with ranges: `max_hosts >= 1`, `snaplen 64..=262144`, `buffer_size >= 65536` (document units).
  - **Acceptance:** each bad value fails with exit 2 before any pcap call (test via `Config::try_parse_from`).

- [x] **P1-6 `--interval` deprecation lives in the library and reads process args** **(carried: P1-1)**
  - **Where:** `src/app.rs` `check_interval_deprecated(std::env::args())` is called from `run_sniffer_with_writer`.
  - **Problem:** a library function inspecting `std::env::args()` is a layering violation, pollutes tests, and is invisible anyway (P1-3).
  - **Fix:** declare a hidden `#[arg(long, hide = true, conflicts_with = "duration")] interval: Option<u64>` in `Config`, fold it into `effective_duration_secs()`, and warn in `main.rs` when it is set. Delete `check_interval_deprecated`.

- [x] **P1-7 Decouple the library from the clap struct** **(carried: P1-11, marked done in round 1 but not)**
  - **Where:** `run_sniffer_with_writer(config: Config, …)`; tests build `Config` with a 16-field struct literal.
  - **Fix:** introduce `RunOptions { port, duration, periodic, frequency, max_hosts, sample_bytes, format, emit_empty, key_by }` (no clap derive), `impl From<&Config> for RunOptions`, and take that in `app.rs`. Tests use `RunOptions::default()` + struct update.

- [x] **P1-8 Fail fast on unsupported link types** `(verify)`
  - **Where:** `src/capture.rs`, `src/decode.rs` (`Datalink::Unsupported`).
  - **Problem:** on e.g. an 802.11 or PPP interface every frame becomes a `decode_error` and the run "succeeds" with an empty/odd summary.
  - **Fix:** `PcapCapture::new` and `FileCapture::new` return `SnifferError::UnsupportedDatalink(i32)` (message lists supported types) instead of constructing a source. Add a test with a crafted pcap using linktype 105.

- [x] **P1-9 Count every dropped packet; no silent paths**
  - **Where:** `src/app.rs` — `if let Some(syslog) = parse_syslog_packet(...)` has no `else`.
  - **Problem:** empty/whitespace/NUL-only payloads vanish uncounted. `decode_errors` conflates "not UDP/IPv4/6", "truncated", "unsupported datalink".
  - **Fix:** add `parse_errors` (empty payloads), and split `decode_errors` into `decode_truncated` / `decode_unsupported` (keep `decode_errors` as the sum). Count IPv4 first-fragments (MF set, offset 0: currently decoded as if complete with a truncated payload) in `fragmented_first`.
  - **Acceptance:** counters asserted for each path.

- [x] **P1-10 `--debug` and `--no-sample` leak message bodies**
  - **Where:** `src/app.rs` `debug!("Captured from … {}", truncate_utf8(&syslog.message, sample_bytes.max(64)))`.
  - **Problem:** with `--no-sample` / `--sample-bytes 0` the operator asked for no message content, yet `--debug` still logs 64 bytes of every message.
  - **Fix:** when `sample_bytes == 0` log only host, source IP and length. README: state that `--debug` logs message content.

- [x] **P1-11 VLAN-tagged traffic is decoded but never captured** `(verify)`
  - **Where:** `src/capture.rs` filter `udp dst port N`.
  - **Problem:** libpcap's plain `udp dst port` expression assumes untagged Ethernet; 802.1Q-tagged frames (promiscuous capture on a trunk, or drivers that don't strip tags) do not match, although `decode.rs` handles up to three tag types.
  - **Fix:** `udp dst port N or (vlan and udp dst port N)` for Ethernet datalinks (use `cap.get_datalink()` to decide); verify with a crafted tagged pcap replayed through the shared offline filter from P0-2.

- [x] **P1-12 Declared MSRV is wrong** **(verified)**
  - **Where:** `Cargo.toml` `rust-version = "1.80.0"`.
  - **Problem:** `cargo 1.80.1 check --locked` fails: `clap_builder 4.6.2` needs the `edition2024` cargo feature (Rust ≥ 1.85). Anyone building with the advertised MSRV, including distro packagers, fails.
  - **Fix:** set `rust-version = "1.85"` (or the highest dependency requirement; `cargo msrv find` to confirm) and add a CI job: `cargo +<msrv> check --locked --all-targets`.

---

## P2 — tests, performance, code quality

- [x] **P2-1 Unit suite is slow; `Ok(None)` path still polls** **(verified, carried: P2-1)**
  - `cargo test --lib` took **7.9 s** (round-1 acceptance: well under 1 s). Causes: `test_run_sniffer_periodic_interval_report` sleeps 1.1 s plus others, and every `Ok(None)` sleeps 10 ms in real time.
  - **Fix:** inject a `Clock` trait (`now() -> Instant`, `sleep(Duration)`, `system_now()`), use a fake in tests; keep the real one in `main`. Target: lib tests < 1 s.

- [x] **P2-2 Capture loop: finish the busy-loop fix properly** **(carried: P0-2)**
  - **Where:** `src/capture.rs` calls `setnonblock()` and `src/app.rs` sleeps 10 ms on `Ok(None)`.
  - **Verified:** behaviour of `immediate_mode(true)` without nonblock on Linux (TPACKET_V3) blocks indefinitely when idle, causing SIGTERM/deadlines to fail. Non-blocking mode with 10 ms idle sleep is preserved for responsive signal/deadline handling.

- [x] **P2-3 Fuzz + property tests (now justified by P0-1)** **(carried: P2-3)**
  - Add `proptest` (dev-dependency): arbitrary `Vec<u8>` into `parse_syslog_packet` and `decode_datagram` for each `Datalink`; invariants: no panic, `hostname.len() <= payload.len()`, decoded `payload` is a sub-slice of the frame, JSON output re-parses.
  - Add a `cargo-fuzz` target (`fuzz/fuzz_targets/parse.rs`, `decode.rs`) and a weekly scheduled workflow with a short time budget; seed corpus from the unit-test payloads.

- [x] **P2-4 Hot-path allocations remain** **(carried: P2-6, marked done but not)**
  - **Where:** `capture.rs` `packet.data.to_vec()` (copy per packet); `parser.rs` builds a full `String` for the message and another for the hostname per packet (up to ~64 KB); `stats.rs` `src_ip.to_string()` per packet when `--key-by source-ip`.
  - **Fix:** change `PacketSource::next_packet` to lend the buffer (callback `FnMut(&[u8])` or a `Cow`/lifetime-bound packet type); make the parser return borrowed views (`hostname: Option<&str>`, `message: Cow<'_, str>`); allocate only when inserting a new host (and then only `sample_bytes`); key by `IpAddr` for source-ip mode and stringify at report time.
  - **Acceptance:** a criterion benchmark or timed test over 1 M synthetic datagrams; record msgs/s before/after in the PR.

- [x] **P2-5 Integration test is hollow and writes a malformed pcap**
  - **Where:** `tests/integration_test.rs` `test_cli_binary_execution`.
  - **Problem:** the pcap record header writes `caplen`/`len` with `to_be_bytes()` while every other field is native-endian (a typo; on little-endian hosts the lengths are byte-swapped). The 14-byte all-zero "frame" is not a datagram, and the assertion is only `status.success()`, so the test would pass whatever the output.
  - **Fix:** build a valid Ethernet/IPv4/UDP/syslog frame, assert on stdout JSON (host, count, source), and add the unsupported-linktype / bad-file failure cases. Extract the pcap-writer that is copy-pasted in `main.rs`, `capture.rs` and `integration_test.rs` into `tests/common/mod.rs` (or check in small `tests/fixtures/*.pcap` files).

- [x] **P2-6 Remaining test gaps**
  - `test_capture_lo_or_permission_denied` asserts nothing meaningful. Make a root-only `#[ignore]` test that sends a real datagram to a free port and asserts the parsed result; run it in CI with `sudo -E cargo test -- --ignored` **(carried: P2-4)**.
  - e2e: `tests/e2e_periodic_docker.sh` still has `wait "$SNIFFER_PID" || true` (hides crashes) and fixed `sleep` startup races; add cases for SIGTERM → valid final JSON and exit 0 (manually verified OK in this review), non-zero exit for a missing interface, IPv6 `::1`, non-UTF-8 payload, multibyte-after-PRI payload (P0-1), pcap replay with a decoy port (P0-2) **(carried: P2-5)**.
  - Parser table tests for: hostname `255+` bytes, RFC 5424 with structured data containing spaces, PRI `<0>`, `<191>`, `<1>` (single digit), `<>` and `<abc>`.

- [x] **P2-7 Smaller code issues**
  - `PacketSource::get_datalink() -> String` duplicates `datalink()`; delete it and the `Box` forwarding for it.
  - `capture::setup_capture` is only used by tests with hard-coded args; make it `#[cfg(test)]` or delete.
  - Permission detection in `PcapCapture::new` matches substrings of the error text (`"permission"`, `"operation not permitted"`): locale/libpcap-version dependent. Map from the underlying error code / `pcap::Error` variant instead `(verify the variants exposed by pcap 2.4)`.
  - `set_capture_stats` uses `saturating_sub` on cumulative `u32` counters; after a wrap it reports 0 instead of the delta. Use `wrapping_sub`.
  - **(verified)** `capture_stats.received` was 2 when one packet matched the filter and one decoy did not, so libpcap's `ps_recv` counts pre-filter on this platform. Document that `capture_stats.received` is not comparable to `packets_seen`, or rename the field to `kernel_received`.
  - `FileCapture`: a corrupt/truncated pcap currently retries 50× (10 ms apart) before failing as `PersistentCapture`. Offline read errors should be fatal immediately.
  - Report windows: `window_start_instant = Instant::now()` after each report while the schedule uses a fixed deadline, so consecutive windows gap/overlap by a few ms. Derive window start from the previous deadline.
  - One-shot mode with zero traffic prints nothing and exits 0; consumers see EOF instead of a summary. Decide per Decisions (default `--emit-empty` in one-shot mode) and document.

---

## P3 — Docker, CI/CD, supply chain

Round-1 boxes P3-5 and P3-7 were ticked but are only partly done; the missing pieces are listed again here.

- [x] **P3-1 Release gating and provenance** **(carried: P3-5)**
  - README/`docs/WORKFLOW_SUMMARY.md` and the draft-release step imply a human review, but `publish-docker` is wired directly after `create-release` (once P1-1 is fixed it would push `latest` before anyone reviews the draft). Implement the gate (`on: release: types: [published]` or a protected Environment with required reviewers) or state clearly in docs that publishing is automatic.
  - `publish-docker` still has `packages: write` but pushes to Docker Hub: remove.
  - Add `provenance: mode=max` and `sbom: true` to `docker/build-push-action`, keyless cosign signing (or `actions/attest-build-provenance`) for binaries and image, and a `SHA256SUMS` release asset.

- [x] **P3-2 Pin actions by commit SHA; add `--locked` everywhere** **(carried: P3-5, P3-7)**
  - `ci.yml` uses mutable tags/branches (`actions/checkout@v7`, `docker/*@v4/v7`, `softprops/action-gh-release@v3`, `taiki-e/install-action@cargo-tarpaulin`, `dtolnay/rust-toolchain@stable`, `stefanzweifel/git-auto-commit-action@v7`, …) while `security.yml` pins by SHA (and uses `checkout` v4.2.2). Renovate is configured with `helpers:pinGitHubActionDigests` but the workflows are not pinned yet: pin them now and unify checkout versions. `(verify)` every referenced major version exists.
  - None of `cargo fmt/clippy/test/auditable build` use `--locked`; the **release job builds with `cargo auditable build --release` (no `--locked`)**, so shipped binaries are not guaranteed to match the tested lockfile. Add `--locked` to every cargo invocation.
  - Add `cargo deny check` (advisories, licenses, bans) or `cargo audit`, `cargo doc` with `RUSTDOCFLAGS=-D warnings`, and the MSRV job (P1-12). Use `make lint` in CI so there is one definition.

- [x] **P3-3 Coverage job: write token on PRs, fragile badge** **(carried: P3-6)**
  - `coverage` has `contents: write` and runs on `pull_request`, so PR code runs beside a write-scoped token; it commits `coverage.svg` on every push (noise, and a source of HEAD~1 confusion). `curl … > coverage.svg` has no `-fsSL`, so a shields.io error page gets committed as the badge; coverage is scraped from `cobertura.xml` with `grep -o … | head -1`.
  - **Fix:** run the badge-commit step only on `push` to `main` in a separate job; `curl --fail --silent --show-error --retry 3`; parse with `xmllint`/`jq` or `cargo tarpaulin --out Json`; or drop the committed badge for Codecov/gist.

- [x] **P3-4 The published image is never the image that is tested** **(carried: P3-4)**
  - CI e2e-tests the source-built `Dockerfile` image (amd64). The published image comes from `Dockerfile.release`: binaries cross-built on `ubuntu-latest` against Ubuntu glibc/libpcap (via the `ports.ubuntu.com` apt rewrite), dropped onto Debian trixie. arm64/armv7 binaries are never executed in CI.
  - **Fix:** build release binaries inside Debian trixie via one multi-platform `buildx` build, smoke-test every platform under QEMU (`--version`, and a `--read-pcap` replay of a fixture), run the full e2e against the release amd64 image, and build (not publish) the arm targets on PRs.

- [ ] **P3-5 Dockerfile hygiene** **(carried: P3-3)**
  - `FROM rust:slim` floats; pin `rust:<ver>-trixie` and `debian:trixie-slim` (digests via Renovate). `cargo install --locked cargo-auditable` is locked but the tool version is unpinned: add `--version`.
  - No dependency-layer caching (manifests and `src` copied together): use a manifest-first layer, `cargo-chef`, or BuildKit cache mounts.
  - `.dockerignore`: the `.env` entry is still missing from `.dockerignore` (it is in `.gitignore`); add it. The `ansible/` entry is stale now that the directory is gone.

- [ ] **P3-6 Security scans and hooks** **(carried: P3-8)**
  - Trivy runs `fs` only; add `trivy image --ignore-unfixed` on the built image, on a schedule too.
  - `.githooks/pre-commit` runs lint + full tests + a TruffleHog scan of the whole git history + Trivy on every commit; people will bypass it. Make the hook fast (fmt + clippy + secrets on the staged diff); move full scans to `pre-push`/CI. Pin `trufflesecurity/trufflehog` and `aquasec/trivy` images in the Makefile and `bin/renovate/run.sh` (currently `:latest`).

---

## P4 — docs and repo hygiene

- [ ] **P4-1 README and docs**
  - Document the new counters/fields from P0-2, P1-4, P1-9, and the exit-code contract (0 ok, 1 runtime failure, 2 usage error).
  - "Limitations": UDP only; self-reported hostnames and the table-fill evasion (P1-4); IP fragments; VLAN note (P1-11); `ps_recv` semantics (P2-7); `--debug` prints message bodies (P1-10); samples may contain sensitive data.
  - `docs/TESTING.md` / `docs/WORKFLOW_SUMMARY.md`: re-check against the final pipeline after P1-1/P3-1/P3-4 (single CONTRIBUTING.md is fine).

- [ ] **P4-2 CHANGELOG**
  - Add an `## [Unreleased]` section, and note the P0-1 crash as a security fix when it ships. 0.1.40 and 0.1.41 share a date: confirm the 0.1.41 entry is accurate once P1-1 is fixed (it claims Docker hardening and `regex` removal, which match the code).

---

## P5 — backlog (don't start before P0–P2)

- Facility/severity histograms per host (PRI is already parsed in `extract_hostname`; return it).
- TCP/TLS syslog (RFC 6587 framing) or document UDP-only as a hard limit.
- Prometheus `/metrics` or a socket/file sink for long-running mode.
- "Host went silent" detection across windows.

---

## Decisions (defaults to use; do not stop to ask)

| Question | Default |
|---|---|
| Broken pipe exit code | `0`, quietly |
| Default log level | `Warn` (`--debug` → `Debug`, `RUST_LOG` honoured) |
| New JSON fields | additive, `schema_version` stays `1`, documented in README |
| `--interval` | hidden deprecated flag that warns in `main`; remove at 0.2.0 |
| MSRV | `1.85` unless a dependency needs more; enforced by a CI job |
| One-shot mode with no traffic | emit an empty summary (treat as `--emit-empty`); keep the flag for periodic mode |
| Per-packet panic guard | fix the bug (P0-1) and add `catch_unwind` + `parse_errors` as defence in depth |
| Release trigger | single `detect` job output feeding both release jobs; images gated on publishing the draft release |
| Everything else | follow the round-1 "Decisions" table (Renovate with digest pinning, root + `--cap-drop=ALL --cap-add=NET_RAW`, tag-existence check, no `ansible/`) |

## Suggested order of work

1. **P0-1** (parser panic) and **P0-2** (pcap ignores `--port`), each with tests; ship as a patch release.
2. **P1-1** (release pipeline) so the fix can actually be published; then P1-2, P1-3, P1-5, P1-6, P1-7.
3. P1-4, P1-8 … P1-12, then P2 (tests/perf). P2-3 (fuzz) can start right after P0-1.
4. P3 pipeline work after P1-1; P3-1 and P3-4 touch the same workflow, so do them together.
5. P4 docs last so they describe the final behaviour.
