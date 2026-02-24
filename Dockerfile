# ============================================================
# Starcoin Bridge - Dockerfile
# ============================================================
# Multi-stage build for bridge server binary
# Optimized to only build starcoin-bridge binary
# ============================================================

# Build stage
FROM rust:1.86.0-slim as builder

# Proxy configuration (can be passed via --build-arg)
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG http_proxy
ARG https_proxy
ARG NO_PROXY
ARG no_proxy

# Git revision for bin_version macro (can be passed via --build-arg)
# If not provided, will use "docker-build" as fallback
ARG GIT_REVISION="docker-build"

# Set proxy environment variables for apt, git, cargo, etc.
ENV HTTP_PROXY=${HTTP_PROXY}
ENV HTTPS_PROXY=${HTTPS_PROXY}
ENV http_proxy=${http_proxy}
ENV https_proxy=${https_proxy}
ENV NO_PROXY=${NO_PROXY}
ENV no_proxy=${no_proxy}

# Configure apt proxy if provided
RUN if [ -n "$HTTP_PROXY" ] || [ -n "$http_proxy" ]; then \
        PROXY_URL=${HTTP_PROXY:-$http_proxy}; \
        echo "Acquire::http::Proxy \"$PROXY_URL\";" > /etc/apt/apt.conf.d/proxy.conf; \
        echo "Acquire::https::Proxy \"$PROXY_URL\";" >> /etc/apt/apt.conf.d/proxy.conf; \
    fi

# Use Chinese mirror sources for better network access in China
# You can override with --build-arg MIRROR_URL=...
ARG MIRROR_URL
RUN if [ -n "$MIRROR_URL" ]; then \
        sed -i "s|http://deb.debian.org|$MIRROR_URL|g" /etc/apt/sources.list.d/debian.sources || \
        sed -i "s|http://deb.debian.org|$MIRROR_URL|g" /etc/apt/sources.list; \
        sed -i "s|http://security.debian.org|$MIRROR_URL|g" /etc/apt/sources.list.d/debian.sources || \
        sed -i "s|http://security.debian.org|$MIRROR_URL|g" /etc/apt/sources.list; \
    else \
        # Use Aliyun mirror by default for better access in China
        sed -i 's|http://deb.debian.org|http://mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
        sed -i 's|http://deb.debian.org|http://mirrors.aliyun.com|g' /etc/apt/sources.list; \
        sed -i 's|http://security.debian.org|http://mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
        sed -i 's|http://security.debian.org|http://mirrors.aliyun.com|g' /etc/apt/sources.list; \
    fi

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    librocksdb-dev \
    clang \
    cmake \
    git \
    ca-certificates \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy workspace configuration files first (for better layer caching)
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./

# Copy all dependency packages (excluding bridge itself for better caching)
# Base dependencies
COPY bin-version/ ./bin-version/
COPY fastcrypto/ ./fastcrypto/
COPY fastcrypto-derive/ ./fastcrypto-derive/
COPY shared-crypto/ ./shared-crypto/
COPY starcoin-metrics/ ./starcoin-metrics/
COPY telemetry-subscribers/ ./telemetry-subscribers/
COPY prometheus-closure-metric/ ./prometheus-closure-metric/

# Starcoin bridge core dependencies
COPY starcoin-bridge-vm-types/ ./starcoin-bridge-vm-types/
COPY starcoin-bridge-types/ ./starcoin-bridge-types/
COPY starcoin-bridge-sdk/ ./starcoin-bridge-sdk/
COPY starcoin-bridge-json-rpc-types/ ./starcoin-bridge-json-rpc-types/
COPY starcoin-bridge-json-rpc-api/ ./starcoin-bridge-json-rpc-api/
COPY starcoin-bridge-config/ ./starcoin-bridge-config/
COPY starcoin-bridge-keys/ ./starcoin-bridge-keys/
COPY starcoin-bridge-authority-aggregation/ ./starcoin-bridge-authority-aggregation/
COPY starcoin-bridge-sql-macro/ ./starcoin-bridge-sql-macro/
COPY starcoin-bridge-macros/ ./starcoin-bridge-macros/
COPY starcoin-bridge-metrics-push-client/ ./starcoin-bridge-metrics-push-client/

# Indexer dependencies (required by bridge)
COPY bridge-schema/ ./bridge-schema/
COPY starcoin-bridge-field-count/ ./starcoin-bridge-field-count/
COPY starcoin-bridge-indexer-alt-metrics/ ./starcoin-bridge-indexer-alt-metrics/
COPY starcoin-bridge-indexer-builder/ ./starcoin-bridge-indexer-builder/
COPY starcoin-bridge-pg-db/ ./starcoin-bridge-pg-db/

# Required workspace members (even if not directly used, needed for workspace resolution)
COPY bridge-indexer-monitor/ ./bridge-indexer-monitor/
COPY bridge-cli/ ./bridge-cli/
COPY starcoin-rpc-proxy/ ./starcoin-rpc-proxy/

# Copy bridge package last (changes most frequently)
COPY bridge/ ./bridge/

# Build only the starcoin-bridge binary in release mode
# Set GIT_REVISION environment variable to avoid git query during build
RUN GIT_REVISION=$GIT_REVISION cargo build --release --bin starcoin-bridge

# Runtime stage
FROM debian:bookworm-slim

# Proxy configuration (can be passed via --build-arg)
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG http_proxy
ARG https_proxy

# Proxy configuration (can be passed via --build-arg)
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG http_proxy
ARG https_proxy

# Configure apt proxy if provided
RUN if [ -n "$HTTP_PROXY" ] || [ -n "$http_proxy" ]; then \
        PROXY_URL=${HTTP_PROXY:-$http_proxy}; \
        echo "Acquire::http::Proxy \"$PROXY_URL\";" > /etc/apt/apt.conf.d/proxy.conf; \
        echo "Acquire::https::Proxy \"$PROXY_URL\";" >> /etc/apt/apt.conf.d/proxy.conf; \
    fi

# Use Chinese mirror sources for better network access in China
ARG MIRROR_URL
RUN if [ -n "$MIRROR_URL" ]; then \
        sed -i "s|http://deb.debian.org|$MIRROR_URL|g" /etc/apt/sources.list.d/debian.sources || \
        sed -i "s|http://deb.debian.org|$MIRROR_URL|g" /etc/apt/sources.list; \
        sed -i "s|http://security.debian.org|$MIRROR_URL|g" /etc/apt/sources.list.d/debian.sources || \
        sed -i "s|http://security.debian.org|$MIRROR_URL|g" /etc/apt/sources.list; \
    else \
        # Use Aliyun mirror by default for better access in China
        sed -i 's|http://deb.debian.org|http://mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
        sed -i 's|http://deb.debian.org|http://mirrors.aliyun.com|g' /etc/apt/sources.list; \
        sed -i 's|http://security.debian.org|http://mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
        sed -i 's|http://security.debian.org|http://mirrors.aliyun.com|g' /etc/apt/sources.list; \
    fi

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    libpq5 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -m -u 1000 bridge && \
    mkdir -p /app /config && \
    chown -R bridge:bridge /app /config

# Copy binary from builder
COPY --from=builder /build/target/release/starcoin-bridge /app/starcoin-bridge

# Set working directory
WORKDIR /app

# Switch to non-root user
USER bridge

# Expose ports
EXPOSE 9191 9184

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:9191/health || exit 1

# Default command (expects config file to be mounted)
ENTRYPOINT ["/app/starcoin-bridge"]
CMD ["--config-path", "/config/config.yaml"]