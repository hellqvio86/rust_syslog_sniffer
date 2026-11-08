# Build stage (Debian Trixie-based)
FROM rust:slim AS builder

# Install build dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests and source
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build the application in release mode
RUN cargo install --locked cargo-auditable
RUN cargo auditable build --release --locked

# Runtime stage (Debian Trixie slim)
FROM debian:trixie-slim

# Install runtime dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    libpcap0.8t64 \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary from builder
COPY --from=builder /app/target/release/syslog_sniffer /usr/local/bin/syslog_sniffer

RUN chmod +x /usr/local/bin/syslog_sniffer

ENTRYPOINT ["/usr/local/bin/syslog_sniffer"]
CMD ["--help"]
