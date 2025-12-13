# GitHub Workflows Summary

## Workflow Files

### 1. `.github/workflows/ci.yml` - Main CI/CD Pipeline
**Triggers:** Push to main, Pull Requests

**Jobs:**
1. **build-and-test** - Core Rust validation
   - Format checking
   - Clippy linting
   - Unit tests

2. **docker-build-and-test** - Docker validation
   - Build Docker image (amd64)
   - Run E2E tests in Docker

3. **coverage** - Code coverage
   - Generate coverage reports
   - Update coverage badge

4. **build-release-binaries** - Multi-arch binaries
   - Build for amd64, arm64, armhf
   - Upload as artifacts

5. **create-release** - Automated release creation
   - Uses custom action to detect version changes
   - Creates draft release with binaries
   - Only runs if version in Cargo.toml changed

### 2. `.github/workflows/publish-docker.yml` - Docker Publishing
**Triggers:** Release published (manual action)

**Jobs:**
1. **publish-docker** - Publish to Docker Hub
   - Downloads release binaries
   - Builds multi-arch Docker images
   - Pushes to docker.io/hellqvio/syslog_sniffer

## Release Process

```
1. Bump version in Cargo.toml
         ↓
2. Push to main
         ↓
3. CI runs:
   - Tests pass
   - Binaries built
   - Draft release created automatically
         ↓
4. Review draft release on GitHub
         ↓
5. Manually publish release
         ↓
6. Docker images built and published
```

## Custom Actions

### `.github/actions/check-version-change`
Reusable action that detects version changes in Cargo.toml
- Returns: changed (bool), version, previous_version
- Used by: ci.yml (create-release job)
