FROM rust:1.88-bookworm AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY build.rs ./
COPY proto ./proto
COPY src ./src
COPY crates/core ./crates/core

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/wevibe-umbral /usr/local/bin/wevibe-umbral

EXPOSE 4460

CMD ["wevibe-umbral", "serve", "--addr", "0.0.0.0:4460"]
