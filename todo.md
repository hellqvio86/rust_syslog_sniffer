# TODO — syslog_sniffer critical review

- **Project:** `syslog_sniffer` v0.1.40 (Rust, libpcap via `pcap` crate, Docker + GitHub Actions release pipeline)
- **Reviewed commit:** `c104193` (2026-11-08)
- **Method:** static read of every source, script, workflow and doc. **Nothing was compiled or run** (no Rust toolchain in the review sandbox). Items tagged `(verify)` rest on library/runtime behaviour that should be confirmed empirically before or while fixing.

## Rules for the agent

1. Work top-down by priority. One task = one commit, conventional-commit style (the repo uses `fix(...)`, `feat(...)`, `chore(...)`).
2. **Do NOT bump `version` in `Cargo.toml`** unless told to. A version change on `main` automatically tags a release, builds binaries and pushes Docker Hub `latest` (see P3-5).
3. After every task: `make lint && make test` must pass (`cargo clippy --all-targets -- -D warnings`, `cargo fmt -- --check`). Unit tests must not need root. Root-only tests go behind `#[ignore]`.
4. Don't change CLI flags or JSON output incompatibly without a flag/deprecation path. See "Decisions" at the bottom for defaults to use when no answer is given.
5. Every behaviour change needs a test with a real assertion. Add or update README usage when flags change.
6. No `unsafe` in this crate (keep it that way, see P2-7).

## What is good (don't regress)

- Clean split: `lib` (parse) / `app` (loop) / `capture` (pcap) / `stats`, with a `PacketSource` trait that makes the loop mockable.
- `Cargo.lock` committed, `cargo-auditable` + CycloneDX SBOM, TruffleHog/Trivy in CI, SHA-pinned actions in `security.yml`, CODEOWNERS, Dependabot cooldown.
- No `unsafe`, no `unwrap` on network data (the only `unwrap`s are on static regexes and JSON serialization).
- No secrets found in the working tree or in git history (`ghp_xxx` in `bin/renovate/run.sh` is a help-text placeholder).

---

## P0 — wrong results / resource-unsafe behaviour (fix first)

- [x] **P0-1 Decode Ethernet/IP/UDP properly; stop scanning for `<`**
  - **Where:** `src/app.rs:39-46`, `src/capture.rs:36-49`, `src/lib.rs:45-74`.
  - **Problem:** `PcapCapture` hands the *entire frame* (link + IP + UDP headers + payload) to the app. The app takes the first `0x3C` byte anywhere in the frame as the start of the syslog message. A `0x3C` inside the headers (IP total-length 60, an IP octet 60, a random ID/checksum byte, a port) makes the "message" start inside the header. The result is garbage text, hostname `Unknown`, or the packet silently dropped by the UTF-8 check. If there is no `0x3C`, the whole frame (MAC bytes included) is parsed and almost always fails UTF-8, so the packet is dropped silently. Ethernet padding on short frames (zero bytes after the UDP payload) is also never trimmed, so NULs end up in messages. Datalink is only logged (`app.rs:12`) and never used. VLAN tags, IPv6 and `any`/`LINUX_SLL` captures are therefore all unreliable.
  - **Fix:**
    - Add a `decode` module that takes `(datalink, &[u8])` and returns `Option<Datagram { src_ip, dst_ip, src_port, dst_port, payload: &[u8] }>`.
    - Support `EN10MB` (+ 802.1Q/QinQ), `NULL`/`LOOP`, `LINUX_SLL`, `LINUX_SLL2`, `RAW`; IPv4 (honour IHL) and IPv6 (skip known extension headers, count and drop fragments); UDP (use the UDP length field to trim padding).
    - Use a small, well-maintained crate (e.g. `etherparse`) or hand-roll with bounds-checked slices. Justify the choice in the commit message and check the binary size delta on armv7.
    - Expose the datalink as an enum from `PacketSource` instead of a `Debug`-formatted `String` (`lib.rs:17`).
    - Feed only `payload` to `parse_syslog_packet`. Delete the `'<'` heuristic.
  - **Acceptance:** table-driven tests with crafted frames: payload preceded by a header containing `0x3C` at several offsets; padded short frame; VLAN-tagged; IPv6; `lo`-style EN10MB; NULL/LOOP; truncated/garbage frames return `None` without panic. Sample message never contains header bytes or trailing NULs.

- [x] **P0-2 Fix the CPU busy-loop in capture** `(verify)`
  - **Where:** `src/capture.rs:19-20,27-29` + `src/app.rs:61-64`.
  - **Problem:** the capture is put into non-blocking mode (`setnonblock()`), so `next_packet()` returns `TimeoutExpired` immediately when idle (the `timeout(1000)` is then meaningless). The loop `continue`s straight back, pinning one core at ~100% while waiting. The 5 mock-based unit tests also spin for their full 1 s `interval` for the same reason.
  - **Fix:** remove `setnonblock()`; keep blocking reads with a short read timeout (e.g. 100–250 ms) so the deadline/report/signal checks in the loop still run on time. A 1000 ms timeout lets a run overshoot `--interval` by up to 1 s.
  - **Acceptance:** idle CPU on `lo` <1% over 10 s (measure via `/proc/<pid>/stat` or `ps`; record before/after in the PR); e2e scripts still pass; overshoot of `--interval` ≤ the chosen timeout.

- [x] **P0-3 Make capture errors visible and fatal when persistent**
  - **Where:** `src/app.rs:65-68`, `src/capture.rs:41-42`, `src/main.rs`.
  - **Problem:** any capture error (interface went down, etc.) is logged at `debug` only (default level is `Error`, so invisible), sleeps 10 ms, and loops until `--interval` expires. The process then prints an empty summary and exits 0. A monitoring pipeline can't tell "no syslog traffic" from "sniffer is blind". `run_sniffer` returns `()`, so it can't signal failure at all.
  - **Fix:**
    - `run_sniffer` returns `Result<(), SnifferError>`; `main` returns `ExitCode`.
    - Log capture errors at `warn`/`error` (rate-limited, e.g. once per second).
    - Abort with non-zero exit after N consecutive errors (e.g. 50) or on fatal pcap errors such as `NoMorePackets`/`PcapError`.
    - Add permission hints to the open error: "needs CAP_NET_RAW or root" (`capture.rs:21`).
  - **Acceptance:** a mock source returning `Err` repeatedly makes `run_sniffer` return `Err` and `main` exit non-zero; message visible at default log level.

- [x] **P0-4 Bound memory — all keys and samples come from untrusted packets**
  - **Where:** `src/stats.rs:16-38`, `src/app.rs:49-53`.
  - **Problem:** `HashMap<String,(u64,String)>` is keyed by the self-reported hostname; the stored sample is the full first message (up to ~64 KB). One host flooding packets with random hostnames grows memory without bound until the run ends. In non-periodic mode that means the whole `--interval`. A container with no memory limit (the documented `docker run`) gets OOM-killed.
  - **Fix:**
    - `--max-hosts` (default 10 000). Overflow is counted into a single `overflow` bucket and reported as `hosts_overflowed: N`.
    - Truncate hostnames (RFC 5424 max 255) and samples (`--sample-bytes`, default 256, `0` = no sample) on a UTF-8 boundary.
    - Also remove the name collision where a real host named `Unknown` merges with "no hostname" (`app.rs:49-52`): count "no hostname" in a separate field.
  - **Acceptance:** test feeding 1 M unique hostnames keeps `stats` size ≤ `max-hosts` entries; sample never exceeds the cap; overflow count correct.

---

## P1 — behaviour, CLI and output contract

- [x] **P1-1 Fix the run-duration semantics (`--interval`/`--periodic`/`--frequency`)**
  - **Where:** `src/config.rs:12-19`, `src/app.rs:15-33,72-80`.
  - **Problem:**
    - `--interval` is actually the **total runtime** (the process always exits after it, default 10 s), while `--frequency` is the report period. The names suggest the opposite, and `--periodic` mode also exits after `--interval`. There is no way to run as a long-lived collector.
    - `--frequency` is silently ignored without `--periodic`.
    - `--interval 0` exits immediately with an empty report.
    - `--frequency 0` with `--periodic` reports on every loop iteration.
    - The final partial window in periodic mode reports `last_report_time.elapsed().as_secs()`, which truncates to `0` for sub-second windows even when it contains messages.
    - The report schedule drifts: `last_report_time = Instant::now()` after each report instead of advancing a fixed deadline.
  - **Fix:** add `--duration <SECS>` (`0` = run until signalled); keep `--interval` as a deprecated alias for one minor version (clap `alias` + a warn log); with `--periodic` and no `--duration`, run until signalled. Validate: `frequency >= 1`, `frequency` requires `--periodic` (`requires = "periodic"`), `frequency <= duration` when both are set. Use a fixed deadline schedule for windows. Report the actual window length (see P1-4).
  - **Acceptance:** tests (with the clock abstraction from P2-1) for 0 / forever, schedule without drift, final partial window length.

- [x] **P1-2 Handle SIGINT/SIGTERM; flush the final summary**
  - **Problem:** no signal handling. Under Docker the binary is PID 1 (exec-form `ENTRYPOINT`). A PID 1 process without a SIGTERM handler ignores SIGTERM, so `docker stop` hangs 10 s and then SIGKILLs, losing the current window. This is masked today only because the process self-terminates after `--interval`; it becomes severe once P1-1 lands.
  - **Fix:** `signal-hook` or `ctrlc` (with `termination` feature) → atomic flag checked each loop iteration → final summary → exit 0. Consider `docker run --init`/`tini` note in docs.
  - **Acceptance:** e2e test sends SIGTERM and still gets a valid final JSON object and exit code 0; `docker stop` returns in <2 s.

- [x] **P1-3 CLI validation, types and help text**
  - **Where:** `src/config.rs`.
  - `port: usize` (`:9`) accepts `0` and `>65535`. Use `u16` with `value_parser!(u16).range(1..)`.
  - **User-visible bug:** the doc comment on `Config` (`config.rs:3`) is clap-template boilerplate — "Search for a pattern in a file and display the lines that contain it." — and is shown by `--help`. Replace with a real `about`; add `#[command(version)]`; add `help =` for every argument (units, defaults, semantics).
  - Remove the redundant inherent `Config::parse()` shim (`:22-26`); stale comment "Revised helper to match main.rs logic exactly" (`:28`).
  - Reject empty `--interface`.
  - **Acceptance:** `syslog_sniffer --help` documents all flags correctly; bad values fail with clap errors (tests).

- [x] **P1-4 Output contract: schema, timing, ordering, broken pipe**
  - **Where:** `src/stats.rs:4-14`, `src/app.rs:29,79`.
  - Add `schema_version`, `window_start`/`window_end` (RFC 3339 UTC), and a real `interval_seconds: f64`. Keep the old field for compatibility for now.
  - Use `BTreeMap` (or a sorted Vec) so host order is deterministic (HashMap order is random per run, which breaks diffing and flaky-prone assertions).
  - `println!(...unwrap())` panics on `EPIPE` (`syslog_sniffer ... | head`) and on any stdout error. Write via a locked `stdout` with `io::Result`; treat `BrokenPipe` as clean exit.
  - Add `--format {pretty,ndjson}`. Default stays `pretty` for now (e2e and README assume it); recommend `ndjson` (one compact object per line) for periodic/long-running use, because multi-line pretty JSON is awkward for log shippers. Add `--emit-empty` to emit heartbeat windows with zero hosts (silence ≠ dead).
  - Data → stdout, logs → stderr; state this in README.
  - **Acceptance:** golden-file tests for both formats; `| head -c1` doesn't panic.

- [x] **P1-5 Report capture health, not just per-host counts**
  - **Problem:** a sniffer that silently loses packets under-reports with no indication. Packets rejected by the UTF-8 check or by the parser are not counted anywhere.
  - **Fix:** add to each window: `packets_seen`, `datagrams_decoded`, `no_hostname`, `non_utf8`, `decode_errors`, `hosts_overflowed`, and libpcap `ps_recv`/`ps_drop`/`ps_ifdrop` deltas via `Capture::stats()` (add a defaulted `stats()` to `PacketSource`).
  - **Acceptance:** counters asserted in tests; kernel-drop delta included for the pcap source.

- [x] **P1-6 Record the real sender, not just the claimed hostname** (depends on P0-1)
  - **Problem:** stats are keyed by a hostname taken from message content, which any sender controls. For a blue-team tool, "who is actually sending" matters more than what they claim.
  - **Fix:** per host entry add `sources: ["10.0.0.5", ...]` (capped at 8, plus `sources_truncated`) and optionally `--key-by {hostname,source-ip}`.
  - **Acceptance:** spoofed hostname from two IPs shows both sources.

- [x] **P1-7 Parser correctness gaps**
  - **Where:** `src/lib.rs:26-74`.
  - **Not handled:**
    - RFC 5424 NILVALUE hostname `-` is reported as host `"-"`. Map to "no hostname".
    - RFC 3164 regex requires trailing whitespace after the hostname (`<13>Oct 11 22:14:15 host` with no body doesn't match). When the hostname is absent, the tag is taken as hostname (`<13>Oct 11 22:14:15 su: ...` → `su:`). Reject candidates ending in `:` or containing `[`/`]`.
    - The very common rsyslog/syslog-ng "RFC 3339 timestamp without version" format (`<34>2026-11-08T12:00:00.123456+01:00 host tag: msg`) falls through both regexes → `Unknown`.
    - PRI isn't range-checked (valid 0–191). `\d`/`\s`/`\S` are Unicode-aware in the `regex` crate; use ASCII classes.
    - No trailing `\n`/`\r\n`/`\0` trimming of the message.
  - **Consider:** replace `regex` with a ~60-line hand-written ASCII parser (or `regex-lite`). It's a security tool on untrusted input; fewer dependencies, no Unicode tables (smaller armv7 binary), no backtracking surface. Measure binary size before/after.
  - Optionally return `pri`/`facility`/`severity`/`app_name` and add facility/severity histograms later (P5).
  - **Acceptance:** table-driven tests for each case above plus real captures from rsyslog, syslog-ng, systemd-journal-remote, a Cisco-style line, and a UniFi/OpenWrt-style line.

- [x] **P1-8 Don't drop non-UTF-8 messages**
  - **Where:** `src/lib.rs:50,72`.
  - **Problem:** one invalid byte makes the whole message disappear (`Err(_) => None`), uncounted. RFC 5424 only requires UTF-8 after the BOM, and 3164 senders routinely emit Latin-1 or binary.
  - **Fix:** use `String::from_utf8_lossy` (and count `non_utf8` in P1-5); still return `None` only for empty payloads.

- [x] **P1-9 Sensitive data in output and debug logs**
  - **Problem:** `sample` echoes raw log lines (often containing usernames, IPs, sometimes credentials) to stdout, which Docker/journald/shippers persist. `--debug` logs every full message (`app.rs:54-58`).
  - **Fix:** `--sample-bytes` (P0-4, default 256), `--no-sample`, README warning. Optional `--redact <regex>` later.

- [x] **P1-10 BPF filter and capture options**
  - **Where:** `src/capture.rs:16-25`.
  - `udp port N` matches **source or destination** port, so unrelated traffic from a client whose ephemeral port equals N, or the server's own replies, is captured. Use `udp dst port N`.
  - IP fragments after the first don't carry a UDP header, so BPF `udp port` misses them: large syslog datagrams are silently lost. Document, and count if practical.
  - Add `--promisc` (default off), `--buffer-size` (default libpcap buffer is small for bursty syslog), and `--snaplen`. Document that `NET_ADMIN` is only needed for promiscuous mode `(verify)`.
  - Open-error messages should distinguish permission denied / device not found / device down.

- [x] **P1-11 Typed errors**
  - Replace `Result<_, String>` (`lib.rs:16`, `capture.rs:9,36,51`) and `format!("{:?}", e)` with a `thiserror` enum (`DeviceNotFound`, `Permission`, `Pcap(pcap::Error)`, `Decode`). Needed by P0-3.
  - Decouple `run_sniffer(config: Config, ...)` from the clap struct: pass a plain `RunOptions` so the library doesn't depend on CLI types.

---

## P2 — tests and code quality

- [x] **P2-1 Make the loop testable, then assert on output**
  - **Where:** `src/app.rs:83-223`.
  - **Problem:** the 5 `run_sniffer` tests assert nothing (they only check "doesn't panic") and print to the real stdout. `MockPacketSource` returns `Ok(None)` forever after its queue empties, so each test burns the full 1 s `interval`.
  - **Fix:** inject (a) an output `impl Write`, (b) a `Clock` trait (or an explicit "source exhausted" signal), (c) a shutdown flag. Then assert on the emitted JSON: counts per host, sample = first message, periodic windows reset, final partial window, error handling (P0-3), overflow (P0-4).
  - **Acceptance:** whole unit suite runs in well under 1 s; every `run_sniffer` test has assertions.

- [x] **P2-2 Parser tests that cover the parser**
  - `lib.rs` tests don't test hostname extraction at all (valid / empty / invalid-UTF-8 / no-hostname / derive-`Debug` only). The only hostname assertions are in `tests/integration_test.rs` (3164) and the shell e2e (5424). Add the P1-7 table. Delete `test_debug_impls` (`lib.rs:106-127`, tests derive output and `stats` tests that restate the implementation).

- [ ] **P2-3 Fuzz + property tests (untrusted network input)**
  - Add a `cargo-fuzz` target for `decode` + `parse_syslog_packet` and a `proptest` suite: never panics; hostname ≤255 bytes; sample ≤ cap; output always valid JSON. Run fuzz for a short budget in a scheduled workflow (weekly), not on every PR.

- [x] **P2-4 Deterministic capture tests; offline pcap mode**
  - Add `--read-pcap <file>` backed by `Capture::from_file` as another `PacketSource`. This lets tests replay checked-in `.pcap` fixtures with no root, no timing, no sockets (and is useful to users for forensics).
  - `test_capture_lo` (`capture.rs:73-89`) asserts nothing and depends on the host (root or not). Make it `#[ignore]` (root-only) and make it send a real UDP datagram and assert the parsed result; run it in CI with `sudo -E cargo test -- --ignored`.

- [x] **P2-5 Harden the shell e2e tests**
  - `tests/e2e_docker.sh:49`, `e2e.sh:59`: `wait $SNIFFER_PID || true` hides sniffer crashes; capture the exit code and assert it.
  - The "quiet" check greps for `INFO` (`e2e*.sh`) but the default log level is `Error`; grep for `ERROR|WARN|panicked` instead.
  - Fixed `sleep 1/2/3` startup races → poll for readiness. Fixed ports 5514/5141 → pick a free port. Use `trap cleanup EXIT`, `mktemp` for output files (`sniffer_output_periodic.txt` is not in `.gitignore` and survives failures).
  - Stale comments: `e2e_docker.sh:19` says the image defaults to non-root user `sniffer` (no such user exists); `e2e_periodic_docker.sh:63` says "total interval is 10s" (it is 20).
  - `tests/e2e.sh` is never run in CI (only the two docker scripts). Either run it (root job) or delete it; it also needs interactive `sudo` and unnecessary `stdbuf`.
  - Test messages: STRUCTURED-DATA has an unbalanced quote (`eventSource=" eventID=`), and "BOM" is literal text, not U+FEFF. Use RFC-compliant samples.
  - **New cases:** RFC 3164, multiple hosts, IPv6 (`::1`), non-UTF-8 payload, SIGTERM (P1-2), non-zero exit when the interface is missing, packet flood hits `max-hosts`.

- [x] **P2-6 Hot-path allocations**
  - **Where:** `src/app.rs:49-53`, `src/stats.rs:33-38`, `src/capture.rs:39`.
  - Each packet: `packet.data.to_vec()` (copy 1), `s.to_string()` (copy 2), then `hostname.clone()` ×2 and `message.clone()` before `add_entry(String, String)`, which `or_insert`s only the first message. The rest are allocated just to be dropped.
  - **Fix:** `add_entry(&mut self, host: &str, msg: &str)` with a `get_mut` fast path; allocate the sample only for new hosts (and truncated); borrow the pcap buffer instead of copying (e.g. `Packet<'_>` return type or callback).
  - Add a simple benchmark (criterion or a timed test over 1 M synthetic datagrams) and record msgs/s before/after in the PR.

- [x] **P2-7 Cargo.toml hygiene**
  - Add `description`, `repository`, `readme`, `keywords`, `categories`, `rust-version` (and a CI job on the MSRV). Consider migrating to edition 2024 (`cargo fix --edition`).
  - Add `[profile.release]`: `lto = "thin"`/`"fat"`, `codegen-units = 1`, `strip = "symbols"`; evaluate `panic = "abort"`. Record armv7 binary size before/after.
  - Add `[lints.rust] unsafe_code = "forbid"` (+ `#![forbid(unsafe_code)]` in `lib.rs`/`main.rs` if not using the table) and a curated `[lints.clippy]` set.

- [x] **P2-8 `clippy.toml` is mostly dead config**
  - Several keys tune lints that aren't enabled by default (`cognitive-complexity-threshold` → nursery; `too-many-lines-threshold`, `single-char-binding-names-threshold`, `max-struct-bools`, `max-trait-bounds`, `doc-valid-idents` → pedantic). `(verify with `cargo clippy -- -W clippy::pedantic`)`. Either enable those groups in `[lints.clippy]` and fix the findings, or delete the unused keys. Add the missing trailing newline.

---

## P3 — Docker, CI/CD, supply chain (this repo advertises supply-chain security; hold it to that)

- [x] **P3-1 Runtime image: ship the runtime lib, not the dev package**
  - `Dockerfile:28-31` and `Dockerfile.release:4-6` install `libpcap-dev` (headers + extra dev dependencies) in the *runtime* stage. Use the runtime package (`libpcap0.8t64` on trixie `(verify exact name with apt-cache)`), `--no-install-recommends`; drop `ca-certificates` (no TLS in this tool).
  - README claims ~15 MB / ~30 MB images (`README.md:151-153`); re-measure and correct. (`docs/DOCKER_DEPLOYMENT.md:68` itself uses `libpcap0.8`.)

- [x] **P3-2 Least privilege at runtime; stop recommending `--privileged`**
  - The image runs as root; `Dockerfile.release:8-10` has the non-root user commented out; README and e2e use `--user root`. `README.md:125-127` labels `--privileged` as "Recommended". For a security tool that's the wrong default advice.
  - **Fix (pick one, prove with e2e):**
    - (a) non-root user + `setcap cap_net_raw+eip /usr/local/bin/syslog_sniffer` (needs `libcap2-bin` in the build stage). **Do not** combine with `--security-opt no-new-privileges` — NNP disables file capabilities.
    - (b) root-in-container with `--cap-drop=ALL --cap-add=NET_RAW --read-only --security-opt no-new-privileges`.
  - Verify whether `NET_ADMIN` is needed at all for non-promiscuous capture `(verify)`; drop it from README, Makefile, and e2e scripts if not.
  - Replace the "disable SELinux/AppArmor" advice with a narrow troubleshooting note.

- [ ] **P3-3 Dockerfile build hygiene**
  - Pin `rust:<version>-trixie` and `debian:trixie-slim` (by digest; let the update bot bump them). `Dockerfile:2` uses floating `rust:slim`.
  - `RUN cargo install cargo-auditable` (`:20`) is unpinned and not `--locked`. Pin the version, add `--locked`; use `cargo auditable build --release --locked`.
  - No dependency-layer caching (manifests and `src` copied together): every source change rebuilds all deps. Use a manifest-first layer, `cargo-chef`, or BuildKit cache mounts.
  - Extend `.dockerignore`: `.env`, `docs`, `ansible`, `tests`, `*.txt`.

- [ ] **P3-4 The published image is never the thing that's tested**
  - CI e2e-tests the **source-built `Dockerfile` image (amd64 only)**. The published image is `Dockerfile.release`: binaries cross-built on `ubuntu-latest` (Ubuntu glibc + Ubuntu libpcap, via the `ports.ubuntu.com` apt hack at `ci.yml:156-178`) and dropped onto Debian trixie. The arm64 and armv7 binaries are never executed in CI.
  - **Fix:** build release binaries and images from the same multi-platform `buildx` build inside Debian trixie (removes the apt-sources hack and the glibc/libpcap mismatch), then smoke-test every platform under QEMU (`docker run --platform ... image --version`/`--help`) and run the full e2e on the amd64 release image. Add a PR path that builds (not publishes) the arm targets so breakage shows up before `main`.

- [x] **P3-5 Release pipeline correctness**
  - **Version detection is fragile** (`.github/actions/check-version-change/action.yml:25`, `ci.yml:238-242,295-297`): compares `HEAD~1:Cargo.toml` with `fetch-depth: 2`. A push containing several commits, or the bot's badge commit landing in between, makes a real version bump invisible → silently no release. Tag creation (`ci.yml:263`) fails on re-run because the tag exists. **Fix:** derive version from `Cargo.toml`, release only if tag `vX.Y.Z` does not already exist (`git ls-remote --tags` / `gh release view`), idempotently — or trigger on tag push / `release: published`.
  - **Docs vs. reality:** `docs/WORKFLOW_SUMMARY.md` says Docker publishing is a separate `publish-docker.yml` triggered when a human publishes the draft release. There is no such file: `publish-docker` runs in `ci.yml` with `needs: create-release`, so images (including `latest`) are pushed to Docker Hub **immediately**, before anyone reviews the draft. Either implement the documented gate (`on: release: types: [published]`, or a protected Environment with required reviewers) or fix the docs.
  - **Provenance:** README advertises SBOMs, but the published image has no attestations. Add `provenance: mode=max` and `sbom: true` to `build-push-action`, build-provenance attestation / cosign keyless signing for image and binaries, and a `SHA256SUMS` release asset.
  - **Permissions:** `publish-docker` has `packages: write` (`ci.yml:287`) but pushes to Docker Hub; remove. Scope `contents: write` to the smallest job.
  - **Pin third-party actions by commit SHA** like `security.yml` does. `ci.yml` uses mutable tags/branches (`@v7`, `@stable`, `taiki-e/install-action@cargo-tarpaulin`, `stefanzweifel/git-auto-commit-action`, `softprops/action-gh-release`, etc.). `security.yml` pins `checkout` at v4.2.2 while `ci.yml` uses `@v7` — unify. Also confirm every referenced major version actually exists `(verify — the reviewer could not)`; keep SHAs updated through the bot.

- [ ] **P3-6 Coverage job: write token + noise + fragile badge**
  - `ci.yml:91-128`: the job has `contents: write` and runs on `pull_request` too, so PR-authored code (tests, `build.rs`) runs next to a write-scoped token. It commits `coverage.svg` to `main` on every push (history is full of "Update coverage badge" commits, which also feed the HEAD~1 problem in P3-5). `curl ... > coverage.svg` (`:122`) has no `-fsSL`, so a shields.io outage commits an HTML error page as the badge.
  - **Fix:** run the write step only on `push` to `main` in a separate job; or drop the committed badge in favour of a gist/Codecov/shields endpoint. At minimum use `curl --fail --retry 3`. Also fix `cobertura.xml` parsing (use `cargo tarpaulin --out Json` or `jq`/`xmllint`, not `grep -o` on the first `line-rate`).

- [x] **P3-7 CI checks don't match the local gate**
  - `ci.yml:38` runs `cargo clippy -- -D warnings`; `Makefile:55` runs `--all-targets`. Tests/benches aren't linted in CI. Use `make lint` in CI so there's a single definition.
  - Add `--locked` to cargo commands. Add `cargo deny` (advisories, licences, bans) or `cargo audit`; confirm Trivy `fs` actually covers `Cargo.lock` `(verify)`. Add `cargo doc` with `RUSTDOCFLAGS=-D warnings`. Add the MSRV job from P2-7.

- [ ] **P3-8 `security.yml` and git hooks**
  - Trivy runs `fs` only, which doesn't see the Debian packages in the published image. Add `trivy image` against the built image (with `--ignore-unfixed`), on a schedule too.
  - `.githooks/pre-commit` runs lint + full tests + a TruffleHog scan of the **entire git history** (`Makefile:116-124`, `--only-verified` makes network calls) + Trivy on every commit: slow, so people will bypass it. Scope the hook to staged changes (fast lint + secrets on the diff); keep full scans in CI or `pre-push`.
  - Security tooling is pulled as `:latest` (`Makefile:121,131`, `bin/renovate/run.sh:24` → `ghcr.io/renovatebot/renovate:latest`). Pin versions/digests.

- [x] **P3-9 Two dependency bots + token handling**
  - Both `dependabot.yml` (cargo, github-actions) and `renovate.json` are configured. If both run on the GitHub repo you get duplicate/conflicting PRs. Pick one. If Dependabot stays, add the `docker` ecosystem (base images aren't covered today). If Renovate stays, enable digest pinning (`helpers:pinGitHubActionDigests`, `pinDigests` for Docker) and drop `dependabot.yml` version updates.
  - `bin/renovate/run.sh`: passes `-e "RENOVATE_TOKEN=${TOKEN}"` on the `docker run` command line (visible via `ps`/`docker inspect`) and accepts `--token <value>` (shell history, `ps`). Pass `-e RENOVATE_TOKEN` (inherit from environment) or `--env-file`; drop the CLI flag. The script sources `.env`, but `.env` is in neither `.gitignore` nor `.dockerignore` → add both.

- [x] **P3-10 Makefile**
  - README documents `make docker-run PRIVILEGED=1` and `DOCKER_OPTS="--security-opt ..."` (`README.md:114,126-136`) but `Makefile:65-78` implements neither (variables are silently ignored). Implement `$(DOCKER_OPTS)` or remove the docs (if P3-2 lands, the PRIVILEGED path should simply go away).
  - `.PHONY` (`Makefile:1`) omits `check`, `fmt`, `format`, `coverage`, `sbom`, `docker-tag`, `docker-clean`, `docker-run-interactive`, `all`.
  - `make run` (`:31`) runs bare `cargo run`, which fails (required `--interface`) and needs root; accept `ARGS`.
  - `docker-run` uses `-it` (breaks in CI/non-TTY); `all` includes `sbom`, which `cargo install`s a tool as a side effect.

- [x] **P3-11 Out-of-scope `ansible/` directory**
  - A k3s control-plane cordon/taint/label playbook has nothing to do with a syslog sniffer. Move it to the home-lab repo or delete it.
  - If kept: tasks use `changed_when: "'already cordoned' not in stdout"` etc. (`ansible/roles/k3s_node_scheduling/tasks/main.yml`) with bare `stdout` rather than the registered variable (e.g. `cordon_result.stdout`); likely always-changed or erroring. Run `ansible-lint` and `--check`. `ansible.cfg` sets `host_key_checking = False`.

---

## P4 — documentation and repo hygiene

- [x] **P4-1 README**
  - Usage (`:174-181`) lists 3 options; add `--debug`, `--duration`/`--interval`, `--periodic`, `--frequency`, and the new flags; show sample output; state that the default run exits after N seconds (until P1-1).
  - Add a **Limitations** section: UDP only (no TCP/TLS/RELP syslog), IP fragments, what "hostname" means (self-reported), needs `CAP_NET_RAW`, output may contain sensitive log data.
  - Replace `docker pull ...:0.6.2` (`:89`) — the crate is at 0.1.40, so that example tag is stale/nonexistent; use `<version>`.
  - `make docker-run` with no `ARGS` just prints `--help` (image `CMD`), not "default options" (`:58-59`).
  - Correct size numbers (P3-1) and the privileged-mode advice (P3-2).

- [x] **P4-2 `docs/DOCKER_DEPLOYMENT.md` describes a different project layout**
  - It shows a different Dockerfile (`rust:1.83-trixie`, `/build`, `libpcap0.8`) copying `target/release/rust_syslog_sniffer`. The real binary is `syslog_sniffer` (`Cargo.toml:2`), so the documented Dockerfile would fail. It references a non-existent `README_DOCKER.md` (`:25`) and contains leftover "Integration Steps" instructions. Delete it (the README covers Docker) or rewrite it from the real `Dockerfile`/`Makefile`.

- [x] **P4-3 `docs/TESTING.md`, `docs/WORKFLOW_SUMMARY.md`**
  - Absolute `file:///path/to/rust_syslog_sniffer/...` links (broken for everyone else) → relative links. `WORKFLOW_SUMMARY.md` documents a non-existent `publish-docker.yml` and omits `security.yml`; `TESTING.md` implies `e2e.sh` runs in CI. Update after P3-4/P3-5, or fold into a single CONTRIBUTING.md.

- [x] **P4-4 Ignore files and editor config**
  - `.gitignore`: add `.env`, `sbom*.json`, `*.cdx.json`, `sniffer_output_*.txt`, `/coverage`. Ignoring `.cargo/` is unusual (hides project-level cargo config): confirm it's intentional.
  - `.vscode/settings.json`: `rust-analyzer.cargo.extraArgs: ["--release"]` makes rust-analyzer check in release mode (slower, diverges from `make check`); consider dropping.
  - Add a `CHANGELOG.md` (release notes are auto-generated only).

---

## P5 — backlog / features worth considering (don't start before P0–P2)

- Facility/severity histograms per host (needs PRI parsing from P1-7).
- TCP syslog (RFC 6587 octet-counting and newline framing) — current README title implies "syslog packets" generally; either implement or document UDP-only.
- Prometheus-style `/metrics` or file/socket output sink for long-running mode.
- Per-host rate / "went silent" detection across windows (baseline against the previous window).

---

## Decisions (use these defaults if the maintainer hasn't said otherwise — do not stop to ask)

| Question | Default |
|---|---|
| Default `--format` | keep `pretty`; add `ndjson`; propose switching at 0.2.0 |
| `--interval` | deprecated alias of `--duration`; `--periodic` without duration runs until signalled |
| Docker privilege model | option (b) in P3-2 (root + `--cap-drop=ALL --cap-add=NET_RAW`, read-only, NNP) unless e2e proves (a) works cleanly |
| Dependency bot | Renovate with digest pinning; remove Dependabot version updates but keep security alerts |
| `regex` dependency | remove in favour of a hand-written parser if the fuzz/table tests pass; otherwise `regex-lite` |
| Release trigger | tag-existence check (P3-5), not `HEAD~1` |
| `ansible/` | remove from this repo |

## Suggested order of work

1. P0-1 → P0-2 → P0-3 → P0-4 (correctness first; P0-1 changes the `PacketSource` interface, so do P1-11 typed errors alongside).
2. P2-1 (testable loop) → P1-1/P1-2/P1-3/P1-4/P1-5 → P1-6…P1-10.
3. P2-2…P2-8 in parallel with the above where files don't overlap.
4. P3 (pipeline) once the binary behaves; P3-4 and P3-5 touch the same workflow file, so do them together.
5. P4 docs last, so they describe the final behaviour.
