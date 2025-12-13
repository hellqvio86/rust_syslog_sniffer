# Testing Guide

This document describes the testing strategy and how to run tests for the syslog_sniffer project.

## Test Types

### 1. Unit Tests
Standard Rust unit tests for individual components.

**Run:**
```bash
cargo test
```

**Coverage:**
```bash
cargo tarpaulin --out Html
# View coverage report at tarpaulin-report.html
```

### 2. End-to-End (E2E) Tests

#### Docker E2E Test
Tests the complete Docker workflow with syslog message capture.

**Location:** [`tests/e2e_docker.sh`](file:///home/hellqvio/git/rust_syslog_sniffer/tests/e2e_docker.sh)

**What it tests:**
- Docker image builds successfully
- Container starts and captures syslog messages
- JSON output format is correct
- Application runs quietly (no debug logs in output)

**Run:**
```bash
./tests/e2e_docker.sh
```

**Environment variables:**
- `SKIP_DOCKER_BUILD=1` - Skip the Docker build step (useful in CI when image is already built)

#### Periodic Docker E2E Test
Tests the periodic reporting feature in Docker.

**Location:** [`tests/e2e_periodic_docker.sh`](file:///home/hellqvio/git/rust_syslog_sniffer/tests/e2e_periodic_docker.sh)

**What it tests:**
- Periodic updates work correctly
- Multiple JSON reports are generated
- Messages are captured in different periods
- Statistics reset between periods

**Run:**
```bash
./tests/e2e_periodic_docker.sh
```

**Environment variables:**
- `SKIP_DOCKER_BUILD=1` - Skip the Docker build step

### 3. Integration Tests

#### Standard E2E Test
Tests the binary directly (non-Docker).

**Location:** [`tests/e2e.sh`](file:///home/hellqvio/git/rust_syslog_sniffer/tests/e2e.sh)

**What it tests:**
- Binary builds and runs
- Syslog capture on loopback interface
- RFC 5424 compliant message handling

**Run:**
```bash
./tests/e2e.sh
```

## CI/CD Testing

### GitHub Actions Workflow
All tests run automatically in CI on every push and pull request.

**Workflow:** [`.github/workflows/ci.yml`](file:///home/hellqvio/git/rust_syslog_sniffer/.github/workflows/ci.yml)

**Test stages:**
1. **build-and-test** job:
   - Code formatting check (`cargo fmt`)
   - Linting (`cargo clippy`)
   - Unit tests (`cargo test`)

2. **docker-build-and-test** job:
   - Build Docker image (amd64)
   - Run Docker E2E test
   - Run Periodic Docker E2E test

3. **coverage** job:
   - Generate code coverage report
   - Update coverage badge

## Test Requirements

### System Dependencies
```bash
sudo apt-get install -y libpcap-dev netcat-openbsd make
```

### Docker
- Docker must be installed and running
- User must have permission to run Docker commands

### Network Permissions
Some tests require:
- Ability to capture packets on loopback interface
- Ability to bind to UDP ports
- May require `sudo` for packet capture on some systems

## Writing New Tests

### Unit Tests
Add tests in the same file as the code:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_something() {
        // Test code
    }
}
```

### E2E Tests
Create a new shell script in `tests/`:
1. Make it executable: `chmod +x tests/your_test.sh`
2. Follow the pattern from existing E2E tests
3. Add to CI workflow if needed

## Troubleshooting

### Docker E2E Tests Fail
- Ensure Docker is running: `docker ps`
- Check port availability: `netstat -tuln | grep 5514`
- Verify image built: `docker images | grep syslog_sniffer`

### Permission Errors
- Packet capture may require elevated privileges
- Try running with `sudo` for local testing
- CI runs with appropriate capabilities

### Timing Issues
- E2E tests use sleep to wait for processes
- Slow systems may need longer wait times
- Adjust sleep durations in test scripts if needed

## Coverage Goals

- **Target:** >80% code coverage
- **Current:** ![Coverage](../coverage.svg)
- Coverage badge auto-updates on every CI run

## Test Data

### Sample Syslog Message (RFC 5424)
```
<165>1 2025-12-13T08:00:00.000Z mymachine.example.com appname[su] - ID47 [exampleSDID@32473 iut="3" eventSource=" eventID="1011"] BOMAn application log entry...
```

**Format breakdown:**
- `<165>` - Priority (facility 20, severity 5)
- `1` - Version
- `2025-12-13T08:00:00.000Z` - Timestamp (ISO 8601)
- `mymachine.example.com` - Hostname
- `appname[su]` - App name with process info
- `-` - Process ID (nil)
- `ID47` - Message ID
- `[exampleSDID@32473 ...]` - Structured data
- `BOM...` - Message text
