# GitHub Workflows Summary

## Workflow Files

### 1. `.github/workflows/ci.yml` - Main CI/CD Pipeline
**Triggers:** Push to `main`, Pull Requests, and Release published

**Jobs:**
1. **build-and-test** - Core Rust validation
   - Code formatting (`cargo fmt -- --check`)
   - Linting (`cargo clippy --all-targets -- -D warnings`)
   - Unit tests (`cargo test`)

2. **docker-build-and-test** - Docker validation
   - Build Docker image
   - Run E2E tests in Docker (`tests/e2e_docker.sh`)
   - Run Periodic Docker E2E test (`tests/e2e_periodic_docker.sh`)

3. **coverage** - Code coverage
   - Generates coverage metrics

4. **build-release-binaries** - Multi-arch release binaries
   - Builds release binaries for amd64, arm64, and armhf

5. **create-release** - Automated draft release creation
   - Detects version updates
   - Generates release notes and uploads release binaries

6. **publish-docker** - Multi-arch container publish
   - Builds and publishes multi-architecture images to Docker Hub

### 2. `.github/workflows/security.yml` - Security Scanning
**Triggers:** Push to `main`, Pull Requests, and Scheduled daily

**Jobs:**
- **trufflehog** - Secrets scanning
- **trivy** - Vulnerability scanning for repository dependencies

### 3. `.github/workflows/nightly.yml` - Nightly Pipeline
**Triggers:** Daily schedule (03:00 UTC) and manual workflow dispatch
- Extended builds, audits, and dependency hygiene checks
