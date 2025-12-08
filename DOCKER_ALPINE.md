# Alpine Docker Build Guide

This document describes the Alpine Linux-based Docker build for rust_syslog_sniffer.

## Why Alpine?

- **Smaller Images**: ~25-30MB vs ~80MB with Debian Trixie
- **Static Binaries**: MUSL libc produces fully static binaries
- **Security**: Minimal attack surface
- **Performance**: Lower memory footprint

## Quick Start

### Single Architecture Build (Recommended for Local Testing)

```bash
# Build for your current architecture (amd64)
docker build -f Dockerfile.alpine -t rust_syslog_sniffer:alpine-latest .

# Run it
docker run --rm \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --network host \
  rust_syslog_sniffer:alpine-latest \
  --interface eth0 --port 514
```

### Multi-Architecture Build (For Production)

```bash
# Build for all platforms at once
docker buildx build \
  --platform linux/amd64,linux/arm64,linux/arm/v7 \
  -f Dockerfile.alpine.multiarch \
  -t yourusername/syslog_sniffer:alpine-latest \
  --push \
  .
```

## Build Methods

### Method 1: Simple Build (Single Architecture)

**File**: `Dockerfile.alpine`

Best for:
- Local development
- Testing
- Single architecture deployments

```bash
# Build
docker build -f Dockerfile.alpine -t rust_syslog_sniffer:alpine .

# Run
docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN --network host \
  rust_syslog_sniffer:alpine --interface eth0
```

### Method 2: Multi-Architecture Build

**File**: `Dockerfile.alpine.multiarch`

Best for:
- Production deployments
- Supporting multiple platforms (x86, ARM, ARM64)
- Publishing to Docker Hub

```bash
# Setup buildx (one time)
docker buildx create --name multiarch-builder --use
docker buildx inspect --bootstrap

# Build and push for all platforms
docker buildx build \
  --platform linux/amd64,linux/arm64,linux/arm/v7 \
  -f Dockerfile.alpine.multiarch \
  -t yourusername/syslog_sniffer:alpine-latest \
  --push \
  .

# Or build and load locally (single platform)
docker buildx build \
  --platform linux/amd64 \
  -f Dockerfile.alpine.multiarch \
  -t rust_syslog_sniffer:alpine \
  --load \
  .
```

## Make Targets

```bash
# Simple single-arch build
make docker-build-alpine

# Multi-arch build and push
make docker-buildx-alpine REGISTRY=docker.io/yourusername

# Run Alpine container
make docker-run-alpine ARGS="--interface eth0"

# Interactive shell for debugging
make docker-run-alpine-interactive
```

## Supported Architectures

- **linux/amd64**: x86_64 Intel/AMD systems
- **linux/arm64**: Raspberry Pi 3B+, 4, 5, and other ARM64 devices
- **linux/arm/v7**: 32-bit Raspberry Pi and ARMv7 devices

## Comparison: Debian Trixie vs Alpine

| Metric | Debian Trixie | Alpine |
|--------|---------------|--------|
| Base Image Size | ~80 MB | ~7 MB |
| Final Image Size | ~80 MB | ~25-30 MB |
| Builder Image | ~1.2 GB | ~800 MB |
| C Library | glibc | musl |
| Binary Linking | Dynamic | Static |
| Build Time | ~5-7 min | ~4-6 min |

## Technical Details

### Rust Targets

Alpine uses MUSL libc targets:
- `x86_64-unknown-linux-musl`
- `aarch64-unknown-linux-musl`
- `armv7-unknown-linux-musleabihf`

### Build Dependencies

| Debian | Alpine | Purpose |
|--------|--------|---------|
| `build-essential` | `gcc`, `g++`, `make`, `musl-dev` | Build tools |
| `pkg-config` | `pkgconfig` | Package config |
| `libpcap-dev` | `libpcap-dev` | Packet capture |
| `ca-certificates` | `ca-certificates` | SSL certs |

## Troubleshooting

### Build Error: "exit code: 1"

If you get build errors with the multi-arch Dockerfile, use the simple single-arch version:

```bash
docker build -f Dockerfile.alpine -t rust_syslog_sniffer:alpine .
```

### "Operation not permitted" when capturing

Ensure proper capabilities:

```bash
docker run --rm \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --network host \
  rust_syslog_sniffer:alpine-latest
```

### Cannot find interface

Use `--network host`:

```bash
docker run --rm \
  --network host \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  rust_syslog_sniffer:alpine-latest \
  --interface eth0
```

### Debug container

Run interactive shell:

```bash
docker run -it --rm \
  --network host \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --entrypoint /bin/sh \
  rust_syslog_sniffer:alpine-latest
```

## CI/CD Integration

The project includes `.github/workflows/docker-alpine.yml` for automated builds.

To enable:

1. Set Docker Hub credentials in GitHub Secrets:
   - `DOCKER_USERNAME`
   - `DOCKER_PASSWORD`

2. Push to main/master branch or create a release

3. Images will be automatically built and pushed

## Migrating from Debian Trixie

### Pull Alpine Image

```bash
docker pull docker.io/hellqvio/syslog_sniffer:alpine-latest
```

### Test Side-by-Side

```bash
# Debian version
docker run ... syslog_sniffer:latest

# Alpine version  
docker run ... syslog_sniffer:alpine-latest
```

## Performance Notes

- Alpine images use static linking for better portability
- Binary size is similar to Debian builds (~5-8 MB)
- Runtime performance is comparable
- Lower memory footprint due to MUSL libc

## Production Recommendations

1. Pin Alpine version: `FROM alpine:3.19` instead of `alpine:latest`
2. Use multi-stage builds to keep images small
3. Regularly update dependencies with `cargo update`
4. Test on target architectures before deployment

## Support

For Alpine-specific issues, open a GitHub issue with the `alpine` label.
