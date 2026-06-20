# ---- build stage ----
FROM rust:1-slim-bookworm AS builder

# pkg-config + ssl headers for reqwest (native-tls).
# libdbus-1-dev is needed by the keyring crate's SecretService backend.
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    libdbus-1-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy only the files needed for a Rust build.
# The Python package tree and test suite are intentionally excluded.
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Build both binaries in release mode with the D-Bus UI enabled.
RUN cargo build --release --features ui \
    && strip target/release/pantalaimon target/release/panctl

# ---- runtime stage ----
FROM debian:bookworm-slim

# libssl3  — reqwest native-tls runtime
# libdbus-1-3 — zbus session bus socket I/O
# dbus       — provides dbus-daemon (needed by entrypoint.sh to start the session bus)
# ca-certificates — TLS root certificates for outbound HTTPS to homeservers
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    libdbus-1-3 \
    dbus \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/pantalaimon /usr/local/bin/pantalaimon
COPY --from=builder /build/target/release/panctl      /usr/local/bin/panctl
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Fixed socket path exported to both the daemon and any exec'd panctl.
ENV DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/pantalaimon-dbus.sock

VOLUME /data
ENTRYPOINT ["/entrypoint.sh"]
# Default: read config and data from the /data volume.
# Set UseKeyring = False in pantalaimon.conf — no OS keyring is available in
# containers; tokens are stored in /data/pan.db instead.
CMD ["-c", "/data/pantalaimon.conf", "--data-path", "/data"]
