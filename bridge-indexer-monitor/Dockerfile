# Multi-stage Dockerfile for bridge-indexer-monitor
# Build stage
FROM rust:1.86.0-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    clang \
    cmake \
    make \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files for dependency resolution
COPY Cargo.toml Cargo.lock ./
COPY rust-toolchain.toml ./

# Copy all workspace member directories
# This ensures all dependencies are available for the build
COPY bridge-indexer-monitor/ ./bridge-indexer-monitor/
COPY bridge-schema/ ./bridge-schema/
# Required workspace members (even if not directly used, needed for workspace resolution)
COPY bridge-cli/ ./bridge-cli/
COPY bridge/ ./bridge/
COPY starcoin-bridge-indexer-alt-metrics/ ./starcoin-bridge-indexer-alt-metrics/
COPY starcoin-bridge-pg-db/ ./starcoin-bridge-pg-db/
COPY starcoin-bridge-indexer-builder/ ./starcoin-bridge-indexer-builder/
COPY starcoin-bridge-field-count/ ./starcoin-bridge-field-count/
COPY starcoin-bridge-config/ ./starcoin-bridge-config/
COPY starcoin-bridge-keys/ ./starcoin-bridge-keys/
COPY starcoin-bridge-authority-aggregation/ ./starcoin-bridge-authority-aggregation/
COPY starcoin-bridge-sql-macro/ ./starcoin-bridge-sql-macro/
COPY starcoin-bridge-macros/ ./starcoin-bridge-macros/
COPY starcoin-bridge-metrics-push-client/ ./starcoin-bridge-metrics-push-client/
COPY starcoin-bridge-json-rpc-api/ ./starcoin-bridge-json-rpc-api/
COPY starcoin-bridge-json-rpc-types/ ./starcoin-bridge-json-rpc-types/
COPY starcoin-bridge-sdk/ ./starcoin-bridge-sdk/
COPY starcoin-bridge-types/ ./starcoin-bridge-types/
COPY starcoin-bridge-vm-types/ ./starcoin-bridge-vm-types/
COPY starcoin-metrics/ ./starcoin-metrics/
COPY starcoin-rpc-proxy/ ./starcoin-rpc-proxy/
COPY telemetry-subscribers/ ./telemetry-subscribers/
COPY fastcrypto/ ./fastcrypto/
COPY fastcrypto-derive/ ./fastcrypto-derive/
COPY shared-crypto/ ./shared-crypto/
COPY prometheus-closure-metric/ ./prometheus-closure-metric/
COPY bin-version/ ./bin-version/

# Build the binaries
RUN cargo build --release \
    -p starcoin-bridge-indexer-monitor --bin bridge-indexer-monitor \
    -p starcoin-bridge-cli --bin starcoin-bridge-cli

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Copy binaries from builder
COPY --from=builder /build/target/release/bridge-indexer-monitor /usr/local/bin/bridge-indexer-monitor
COPY --from=builder /build/target/release/starcoin-bridge-cli /usr/local/bin/starcoin-bridge-cli

# Change ownership to non-root user
RUN chown appuser:appuser /usr/local/bin/bridge-indexer-monitor \
    && chown appuser:appuser /usr/local/bin/starcoin-bridge-cli

# Switch to non-root user
USER appuser

# Expose ports
# 8080: API server (when --api-address is provided)
# 9184: Prometheus metrics (default metrics-address)
EXPOSE 8080 9184

# Set entrypoint
ENTRYPOINT ["bridge-indexer-monitor"]
