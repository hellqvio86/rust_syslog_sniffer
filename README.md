# Rust Syslog Sniffer

[![CI](https://github.com/hellqvio86/rust_syslog_sniffer/actions/workflows/ci.yml/badge.svg)](https://github.com/hellqvio86/rust_syslog_sniffer/actions/workflows/ci.yml)
![Coverage](coverage.svg)

A syslog packet sniffer written in Rust.

## Building and Running

### Local Build

```bash
# Build the project
make build

# Run tests
make test

# Run the application
make run
```

### Docker Build

This project uses a multi-stage Alpine-based Docker build for minimal image size.

#### Build Docker Image

```bash
make docker-build
```

Or manually:

```bash
docker build -t rust-syslog-sniffer:latest .
```

#### Run Docker Container

```bash
# Run with default options
make docker-run

# Run with custom arguments
make docker-run ARGS="--interface eth0 --port 514"

# Run with custom interface (manual docker command)
docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN \
  --network host \
  rust-syslog-sniffer:latest --interface eth0

# Run interactively
make docker-run-interactive
```

**Note:** The container requires `NET_RAW` and `NET_ADMIN` capabilities for packet capture. Using `--network host` allows the container to access the host's network interfaces.

> [!NOTE]
> Capturing on certain interfaces (like `any` or `lo`) might require the container to run in privileged mode or with additional capabilities depending on your system configuration. If you encounter `PcapError("socket: Operation not permitted")`, try running the docker command manually with `--privileged`.

#### Push to Registry

```bash
# Tag and push to your registry
make docker-push REGISTRY=docker.io/yourusername

# Or manually
docker tag rust-syslog-sniffer:latest docker.io/yourusername/rust-syslog-sniffer:latest
docker push docker.io/yourusername/rust-syslog-sniffer:latest
```

### Docker Image Details

- **Base Image:** Alpine Linux (minimal footprint)
- **Build Stage:** rust:1.83-alpine with build dependencies
- **Runtime Stage:** alpine:latest with only runtime dependencies
- **Security:** Runs as non-root user (UID 1000)
- **Size:** ~20-30MB (final image)

### Available Make Targets

Run `make help` to see all available targets:

```
make build              # Build the Rust project
make test               # Run tests
make docker-build       # Build Docker image
make docker-run         # Run Docker container
make docker-push        # Push to registry (requires REGISTRY variable)
make docker-clean       # Remove Docker images
make docker-clean       # Remove Docker images
make clean              # Clean build artifacts
make coverage           # Generate coverage report
```

## Usage

```bash
rust_syslog_sniffer [OPTIONS]

Options:
  --interface <INTERFACE>  Network interface to sniff (e.g., eth0)
  --port <PORT>           Syslog port to monitor (default: 514)
  --help                  Print help information
```

## Development

```bash
# Format code
make format

# Run linter
make clippy

# Check code
# Check code
make check

# Generate coverage
make coverage
# Detailed HTML report will be available at tarpaulin-report.html
```

## CI/CD

This project uses GitHub Actions for continuous integration. The workflow runs on every push and pull request to `main` or `master` branches.

It performs the following checks:
- **Formatting:** Checks code formatting with `cargo fmt`.
- **Linting:** Runs `cargo clippy` to catch common mistakes.
- **Tests:** Runs unit tests with `cargo test`.
- **E2E Tests:** Runs the Docker-based end-to-end test script `tests/e2e_docker.sh`.

## License

[MIT](LICENSE.md)