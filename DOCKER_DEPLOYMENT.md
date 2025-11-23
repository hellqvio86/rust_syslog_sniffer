# Docker Deployment Guide

## Quick Start

1. Place the Dockerfile and updated Makefile in your project root
2. Build the image: `make docker-build`
3. Run the container: `make docker-run`

## Files Included

- **Dockerfile**: Multi-stage Alpine build
- **Makefile**: Updated with Docker targets
- **README_DOCKER.md**: Updated README with Docker instructions

## Integration Steps

1. Copy `Dockerfile` to your project root
2. Merge `Makefile` with your existing Makefile (or replace it)
3. Add the Docker section from `README_DOCKER.md` to your README.md

## Customization

### Change Image Name
Edit the Makefile and change:
```makefile
IMAGE_NAME = your-custom-name
```

### Change Base Image Version
Edit Dockerfile and change:
```dockerfile
FROM rust:1.83-alpine AS builder
```

### Add Build Arguments
Modify Dockerfile to accept build args:
```dockerfile
ARG RUST_VERSION=1.83
FROM rust:${RUST_VERSION}-alpine AS builder
```

## Troubleshooting

### Permission Denied
Ensure the container has necessary capabilities:
```bash
--cap-add=NET_RAW --cap-add=NET_ADMIN
```

### Interface Not Found
Use `--network host` to access host interfaces:
```bash
docker run --network host ...
```

### Build Fails
Check that all dependencies are available:
- libpcap-dev
- musl-dev
- pkgconfig
