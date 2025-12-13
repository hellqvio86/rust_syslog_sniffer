# Docker Deployment Guide (Debian)

This project ships with an officially supported **Debian Trixie–based Docker image**.

---

## Quick Start

1. Place the `Dockerfile` and `Makefile` in the project root
2. Build the image:
   ```bash
   make docker-build
   ```
3. Run the container:
   ```bash
   make docker-run
   ```

---

## Files Included

- **Dockerfile** – Multi-stage Debian Trixie build
- **Makefile** – Docker build & run helpers
- **README_DOCKER.md** – This document

---

## Integration Steps

1. Copy `Dockerfile` to the project root
2. Merge Docker targets into your existing `Makefile`
3. Reference this document from `README.md`

---

## Base Image Policy

This project **only supports Debian Trixie**.

### Why Debian Trixie?
- Stable `libpcap` support
- glibc-based (no musl issues)
- Good cross compile support

---

## Dockerfile

```dockerfile
# ---- Builder stage ----
FROM rust:1.83-trixie AS builder

RUN apt-get update && apt-get install -y \
    libpcap-dev \
    pkg-config \
    clang \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
RUN cargo build --release

# ---- Runtime stage ----
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/rust_syslog_sniffer /usr/local/bin/rust_syslog_sniffer

ENTRYPOINT ["/usr/local/bin/rust_syslog_sniffer"]
```

---

## Makefile Targets

```makefile
IMAGE_NAME ?= rust_syslog_sniffer

docker-build:
	docker build -t $(IMAGE_NAME) .

docker-run:
	docker run --rm -it \
	  --cap-add=NET_RAW \
	  --cap-add=NET_ADMIN \
	  --network host \
	  $(IMAGE_NAME)
```

---

## Runtime Requirements

Packet capture requires elevated privileges:

```bash
--cap-add=NET_RAW --cap-add=NET_ADMIN
```

Host interfaces require:

```bash
--network host
```

---
