# ============================================================================
# Umbra Relay Server - Multi-stage Dockerfile
#
# Stage 1: Build the Rust binary
# Stage 2: Minimal runtime image
# ============================================================================

# Build stage
FROM rust:1.86-bookworm AS builder

WORKDIR /app

# Copy only Cargo files first for dependency caching
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo 'fn main() { println!("placeholder"); }' > src/main.rs
RUN cargo build --release 2>/dev/null || true

# Now copy the actual source
COPY src/ src/
RUN touch src/main.rs && cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd --create-home --shell /bin/bash relay

COPY --from=builder /app/target/release/umbra-relay /usr/local/bin/umbra-relay

# Create data directory for discovery persistence
RUN mkdir -p /data && chown relay:relay /data

USER relay

EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

ENV RUST_LOG=info
ENV RELAY_PORT=8080
ENV MAX_OFFLINE_MESSAGES=1000
ENV OFFLINE_TTL_DAYS=7
ENV SESSION_TTL_SECS=3600
ENV CLEANUP_INTERVAL_SECS=300
# Federation
ENV RELAY_PEERS=""
ENV RELAY_PUBLIC_URL=""
ENV RELAY_ID=""
ENV PRESENCE_HEARTBEAT_SECS=30
# Discovery persistence
ENV DATA_DIR=/data

CMD ["umbra-relay"]
