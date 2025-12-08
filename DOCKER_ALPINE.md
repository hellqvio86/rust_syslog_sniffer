# Alpine Docker Build Guide

This document describes the Alpine Linux-based Docker build for rust_syslog_sniffer.

## Why Alpine?

- **Smaller Images**: ~25-30MB vs ~80MB with Debian Trixie
- **Static Binaries**: MUSL libc produces fully static binaries
- **Security**: Minimal attack surface
- **Performance**: Lower memory footprint

## Quick Start

### Build Alpine Image

```bash
# Build for local architecture
make docker-build-alpine

# Build for all architectures (requires Docker Buildx)
make docker-buildx-alpine REGISTRY=docker.io/yourusername
```

### Run Alpine Container

```bash
# Basic run
make docker-run-alpine ARGS="--interface eth0 --port 514"

# Or directly with docker
docker run --rm \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --network host \
  rust_syslog_sniffer:alpine-latest \
  --interface eth0 --port 514
```

### Pull from Docker Hub

```bash
# Pull Alpine version
docker pull docker.io/hellqvio/syslog_sniffer:alpine-latest

# Run it
docker run --rm \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --network host \
  docker.io/hellqvio/syslog_sniffer:alpine-latest \
  --interface eth0
```

## Supported Architectures

The Alpine build supports the same architectures as the Debian build:

- **linux/amd64**: x86_64 Intel/AMD systems
- **linux/arm64**: Raspberry Pi 3B+, 4, 5, and other ARM64 devices
- **linux/arm/v7**: 32-bit Raspberry Pi and ARMv7 devices

## Multi-Architecture Builds

### Using Docker Buildx

```bash
# Create and use a new builder
docker buildx create --name alpine-builder --use

# Build for all platforms
docker buildx build \
  --platform linux/amd64,linux/arm64,linux/arm/v7 \
  -f Dockerfile.alpine \
  -t your-registry/syslog_sniffer:alpine-latest \
  --push \
  .

# Clean up
docker buildx rm alpine-builder
```

### Build Individual Architectures

```bash
# AMD64
make docker-build-alpine-amd64

# ARM64 (for Raspberry Pi 4/5)
make docker-build-alpine-arm64

# ARMv7 (for Raspberry Pi 3)
make docker-build-alpine-armv7
```

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

Alpine uses MUSL libc targets instead of GNU libc:

- `x86_64-unknown-linux-musl` (instead of `x86_64-unknown-linux-gnu`)
- `aarch64-unknown-linux-musl` (instead of `aarch64-unknown-linux-gnu`)
- `armv7-unknown-linux-musleabihf` (instead of `armv7-unknown-linux-gnueabihf`)

### Build Dependencies

Alpine package equivalents:

| Debian | Alpine | Purpose |
|--------|--------|---------|
| `build-essential` | `gcc`, `g++`, `make`, `musl-dev` | Build tools |
| `pkg-config` | `pkgconfig` | Package config |
| `libpcap-dev` | `libpcap-dev` | Packet capture |
| `ca-certificates` | `ca-certificates` | SSL certs |

## Troubleshooting

### Issue: "Operation not permitted" when capturing

**Solution**: Ensure proper capabilities are set:

```bash
docker run --rm \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --network host \
  rust_syslog_sniffer:alpine-latest
```

### Issue: Cannot find interface

**Solution**: Use `--network host` to access host interfaces:

```bash
docker run --rm \
  --network host \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  rust_syslog_sniffer:alpine-latest \
  --interface eth0
```

### Issue: Debug container

**Solution**: Run interactive shell:

```bash
make docker-run-alpine-interactive

# Or directly
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

3. Images will be automatically built and pushed to Docker Hub

## Migrating from Debian Trixie

If you're currently using the Debian Trixie build:

### Pull Alpine Image

```bash
docker pull docker.io/hellqvio/syslog_sniffer:alpine-latest
```

### Test Side-by-Side

```bash
# Run Debian version
docker run ... syslog_sniffer:latest

# Run Alpine version
docker run ... syslog_sniffer:alpine-latest
```

### Update docker-compose.yml

```yaml
services:
  syslog_sniffer:
    image: docker.io/hellqvio/syslog_sniffer:alpine-latest
    # ... rest of config
```

## Make Targets

All Alpine-specific targets:

```bash
make help-alpine
```

Available targets:
- `docker-build-alpine` - Build Alpine image locally
- `docker-buildx-alpine` - Build multi-arch and push
- `docker-run-alpine` - Run Alpine container
- `docker-run-alpine-interactive` - Debug shell
- `docker-push-alpine` - Push to registry
- `docker-clean-alpine` - Clean up images

## Notes

- Alpine images use static linking, making them more portable
- Binary size is similar to Debian builds (~5-8 MB)
- Runtime performance is comparable to Debian builds
- Consider pinning Alpine version in production: `FROM alpine:3.19`

## Support

For issues specific to the Alpine build, please open an issue on GitHub with the `alpine` label.
