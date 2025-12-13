````markdown
# Trixie Docker Build Guide

This document describes the Debian Trixie-based Docker build for rust_syslog_sniffer.

## Why Trixie?

- **Compatibility**: glibc-based images have broader compatibility with prebuilt artifacts.
- **Stability**: Debian releases provide predictable behavior for production deployments.
- **Ecosystem**: A larger set of packages available via `apt`.

## Quick Start

### Single Architecture Build

```bash
# Build the Trixie image (local architecture)
docker build -f Dockerfile -t rust_syslog_sniffer:trixie-latest .

# Run it
docker run --rm \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --network host \
  rust_syslog_sniffer:trixie-latest \
  --interface eth0 --port 514
```

### Multi-Architecture Build (using buildx)

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64,linux/arm/v7 \
  -f Dockerfile.trixie.multiarch \
  -t yourusername/syslog_sniffer:trixie-latest \
  --push \
  .
```

## Make Targets

```bash
# Simple single-arch build
make docker-build-trixie

# Multi-arch build and push
make docker-buildx-trixie REGISTRY=docker.io/yourusername

# Run Trixie container
make docker-run-trixie ARGS="--interface eth0"
```

## Notes

- The builder stages use the official `rust:1.83-slim` image and runtime uses `debian:trixie-slim`.
- The build uses `cargo build --release` and produces dynamically linked binaries that run on Debian-based images.

````
