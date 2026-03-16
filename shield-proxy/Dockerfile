# Stage 1: Build
FROM rust:1.82 AS builder
WORKDIR /build
COPY shield-core/ shield-core/
COPY shield-proxy/ shield-proxy/
WORKDIR /build/shield-proxy
RUN cargo build --release

# Stage 2: Runtime (minimal image)
FROM gcr.io/distroless/cc-debian12
COPY --from=builder /build/shield-proxy/target/release/shield-proxy /usr/local/bin/shield-proxy
COPY shield-proxy/deploy/shield-proxy.toml /etc/shield-proxy/config.toml
ENV SHIELD_PROXY_CONFIG=/etc/shield-proxy/config.toml
ENV RUST_LOG=info
EXPOSE 8443 5353/udp 9090
ENTRYPOINT ["/usr/local/bin/shield-proxy"]
