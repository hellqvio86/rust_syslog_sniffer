# Contributing to rust_syslog_sniffer

Thank you for your interest in contributing to `rust_syslog_sniffer`!

---

## Code & Safety Standards

1. **Safety First**: `#![forbid(unsafe_code)]` is strictly enforced. No `unsafe` blocks, traits, or functions are allowed under any circumstances.
2. **MSRV**: Build and test with Rust 1.88.0 (`cargo +1.88.0 check --locked --all-targets`).
3. **Bounded Memory**: All data structures tracking network packets, hosts, and senders must remain strictly bounded.
4. **Code Quality**:
   ```bash
   make lint
   cargo test --locked
   ```

---

## Commit & Tagging Conventions

### Conventional Commit Tags
All commit messages must follow [Conventional Commits](https://www.conventionalcommits.org/):
- `feat(...)`: New user-facing features or command-line flags
- `fix(...)`: Bug fixes (e.g., `fix(parser): ...`, `fix(capture): ...`, `fix(ci): ...`)
- `perf(...)`: Performance optimizations
- `docs(...)`: Documentation updates
- `test(...)`: Adding or improving unit/integration/property tests
- `refactor(...)`: Code refactoring without behavior change
- `chore(...)`: Maintenance, dependency bumps, or version bumps (e.g., `chore(release): bump version to 0.2.0`)
- `ci(...)`: CI/CD workflows and automation scripts

### Git Release Tags
All git release tags must strictly adhere to Semantic Versioning with a mandatory lowercase `v` prefix:
- **Format**: `v<MAJOR>.<MINOR>.<PATCH>` (e.g., `v0.1.0`, `v0.2.0`, `v1.0.0`).
- **Rule**: Never create or push raw numeric tags without the leading `v` (e.g., `0.2.0` is strictly forbidden).
- **Pre-releases**: `v<MAJOR>.<MINOR>.<PATCH>-<pre>` (e.g., `v0.2.0-rc.1`).
- **Automation**: CI automatically creates the annotated tag `v<version>` from `Cargo.toml` when a release is drafted on `main`.
