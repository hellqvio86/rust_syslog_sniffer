# Rust Syslog Sniffer

[![CI](https://github.com/hellqvio86/rust_syslog_sniffer/actions/workflows/ci.yml/badge.svg)](https://github.com/hellqvio86/rust_syslog_sniffer/actions/workflows/ci.yml)
![Coverage](coverage.svg)
![GitHub Release](https://img.shields.io/github/v/release/hellqvio86/rust_syslog_sniffer)
![amd64](https://img.shields.io/badge/arch-amd64-blue)
![arm64](https://img.shields.io/badge/arch-arm64-blue)
![armv7](https://img.shields.io/badge/arch-armv7-blue) 

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

### Supported Architectures

- **linux/amd64**: Standard 64-bit Intel/AMD systems
- **linux/arm64**: Raspberry Pi 3, 4, 5, and other ARM64 devices
- **linux/arm/v7**: 32-bit Raspberry Pi and other ARMv7 devices

### Docker Build

#### Alpine Linux Build

For a smaller, more efficient image, you can use the Alpine Linux build:

```bash
# Build Alpine image
make docker-build-alpine

# Run Alpine container
make docker-run-alpine ARGS="--interface eth0 --port 514"

# Multi-architecture build
make docker-buildx-alpine REGISTRY=docker.io/yourusername
```

See [DOCKER_ALPINE.md](DOCKER_ALPINE.md) for complete Alpine build documentation.

**Image Size Comparison:**
- Debian Trixie: ~80MB
- Alpine: ~25-30MB (60-70% smaller)


This project uses a multi-stage Debian-based Docker build for wide compatibility.

#### Build Docker Image

```bash
make docker-build
```

Or manually:

```bash
docker build -t syslog_sniffer:latest .
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
  syslog_sniffer:latest --interface eth0

# Run interactively
make docker-run-interactive
```

#### Manual Docker Usage

The image is published on Docker Hub at: [docker.io/hellqvio/syslog_sniffer](https://hub.docker.com/r/hellqvio/syslog_sniffer)

If you prefer not to use `make`, you can run the Docker container directly using the absolute address:

```bash
# Basic run
docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN --network host \
  docker.io/hellqvio/syslog_sniffer:latest --interface eth0

# With custom arguments
docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN --network host \
  docker.io/hellqvio/syslog_sniffer:latest --interface eth0 --port 1514
```

**Note:** The container requires `NET_RAW` and `NET_ADMIN` capabilities for packet capture. Using `--network host` allows the container to access the host's network interfaces.

##### Troubleshooting
Start bash in the container to debug:

```bash
docker run -it --rm --entrypoint /bin/bash \
  --cap-add=NET_RAW --cap-add=NET_ADMIN --network host \
  docker.io/hellqvio/syslog_sniffer:latest
```

> [!NOTE]
> Capturing on certain interfaces (like `any` or `lo`) might require the container to run in privileged mode or with additional capabilities depending on your system configuration. If you encounter `PcapError("socket: Operation not permitted")`, try running the docker command manually with `--privileged`.

#### Push to Registry

```bash
# Tag and push to your registry
make docker-push REGISTRY=docker.io/yourusername

# Or manually
docker tag syslog_sniffer:latest docker.io/yourusername/syslog_sniffer:latest
docker push docker.io/yourusername/syslog_sniffer:latest
```

### Docker Image Details

- **Base Image:** Debian Trixie Slim (glibc compatibility, optimized size)
- **Size:** ~30MB (final image)

### Available Make Targets

Run `make help` to see all available targets:

```
make build              # Build the Rust project
make test               # Run tests
make docker-build       # Build Docker image
make docker-run         # Run Docker container
make docker-push        # Push to registry (requires REGISTRY variable)
make docker-clean       # Remove Docker images

make clean              # Clean build artifacts
make coverage           # Generate coverage report
```

## Usage

```bash
syslog_sniffer [OPTIONS]

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