# Build stage (Debian Trixie-based)
FROM rust:slim@sha256:f6c4a35d21dbb3c89d7a8d056c193e94fc09037f2b58dd858b09c39a47dd02d7 AS builder

# Install build dependencies with apt cache mount
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libpcap-dev

WORKDIR /app

# Copy manifests and source
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Install cargo-auditable with version pin and cache mount
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo install --locked --version 0.7.7 cargo-auditable

# Build the application in release mode with Cargo cache mounts
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo auditable build --release --locked \
    && cp /app/target/release/syslog_sniffer /usr/local/bin/syslog_sniffer

# Runtime stage (Debian Trixie slim)
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# Install runtime dependencies with apt cache mount
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends \
    libpcap0.8t64

# Copy the binary from builder
COPY --from=builder /usr/local/bin/syslog_sniffer /usr/local/bin/syslog_sniffer

RUN chmod +x /usr/local/bin/syslog_sniffer

ENTRYPOINT ["/usr/local/bin/syslog_sniffer"]
CMD ["--help"]
