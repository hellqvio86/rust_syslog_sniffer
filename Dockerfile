# Build stage
FROM rust:1.83-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    libpcap-dev \
    pkgconfig

# Create app directory
WORKDIR /usr/src/app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build the application in release mode
RUN cargo build --release

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache \
    libpcap \
    libgcc

# Create a non-root user
#RUN addgroup -g 1000 sniffer && \
#    adduser -D -u 1000 -G sniffer sniffer

# Copy the binary from builder
COPY --from=builder /usr/src/app/target/release/syslog_sniffer /usr/local/bin/syslog_sniffer

# Set ownership
#RUN chown sniffer:sniffer /usr/local/bin/syslog_sniffer

# Switch to non-root user
#USER sniffer

# Set the startup command
ENTRYPOINT ["/usr/local/bin/syslog_sniffer"]
CMD ["--help"]