# syntax=docker/dockerfile:1

# ---- Build stage ----
FROM rust:1.79 as builder
WORKDIR /app

# Cache deps
COPY Cargo.toml .
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release || true

# Copy real sources
COPY . .
RUN cargo build --release

# ---- Runtime stage ----
FROM gcr.io/distroless/cc-debian12
WORKDIR /app

# Create runtime directories
VOLUME ["/app/web", "/app/cert", "/app/backups", "/var/log/rust-certbot"]

COPY --from=builder /app/target/release/rust-certbot /usr/local/bin/rust-certbot
COPY config.toml /app/config.toml

EXPOSE 80 8080 443

ENV RUST_LOG=info
ENV RUST_CERTBOT_CONFIG=/app/config.toml

USER 0:0
ENTRYPOINT ["/usr/local/bin/rust-certbot"]