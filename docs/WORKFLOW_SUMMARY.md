# GitHub Workflows Summary

## Workflow Files

### 1. `.github/workflows/ci.yml` - Main CI/CD Pipeline
**Triggers:** Push to `main`, Pull Requests, and Release published (`release: [published]`).

**Jobs:**
1. **detect** - Detects version bumps and release gating
   - Determines if draft release is needed on push to `main`
   - Gates Docker container publishing strictly on GitHub Release publication
2. **build-and-test** - Core Rust validation
   - Code formatting, clippy linter, and documentation check via `make lint`
   - Unit tests (`cargo test --locked`)
   - Root live UDP capture tests (`sudo env "PATH=$PATH" ... cargo test --locked -- --ignored`)
   - Dependency security audit (`cargo audit` via `rustsec/audit-check`)
3. **msrv** - Minimum Supported Rust Version check
   - Validates build compatibility against declared MSRV (Rust 1.88.0)
4. **docker-build-and-test** - Multi-arch Docker validation
   - Multi-platform Buildx build for `linux/amd64`, `linux/arm64`, and `linux/arm/v7`
   - QEMU smoke tests on every platform (`--version` and `--read-pcap` fixture replay)
   - E2E tests in Docker (`tests/e2e_docker.sh` and `tests/e2e_periodic_docker.sh`)
5. **coverage** - Code coverage validation
   - Runs tarpaulin with read-only permissions on PRs (fails under 80% coverage)
6. **update-coverage-badge** - Coverage badge commit
   - Runs only on `push` to `main` to update `coverage.svg`
7. **build-release-binaries** - Multi-arch release binaries
   - Builds auditable release binaries and CycloneDX SBOMs for `amd64`, `arm64`, and `armhf`
8. **create-release** - Automated draft release creation
   - Generates `SHA256SUMS` and SLSA provenance attestations
   - Creates GitHub draft release with release assets
9. **publish-docker** - Multi-arch container publish
   - Gated on GitHub Release publication
   - Builds and pushes multi-architecture images (`linux/amd64`, `linux/arm64`, `linux/arm/v7`) to Docker Hub with `provenance: mode=max` and `sbom: true`

### 2. `.github/workflows/security.yml` - Security Scanning
**Triggers:** Push to `main`, Pull Requests, Scheduled daily (`04:00 UTC`), and manual workflow dispatch.

**Jobs:**
- **trufflehog-scan** - Secret scanning across git history
- **trivy-scan** - Filesystem vulnerability scanning for repository dependencies
- **trivy-image-scan** - Container image vulnerability scan with `--ignore-unfixed`

### 3. `.github/workflows/fuzz.yml` - Weekly Fuzzing Pipeline
**Triggers:** Weekly schedule (Sunday 03:00 UTC) and manual workflow dispatch.
- Continuous fuzz testing using `cargo-fuzz` targeting parser and link-layer decoders.
