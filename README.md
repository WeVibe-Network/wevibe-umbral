<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:02100a,100:2fe07a&height=160&section=header&text=wevibe-umbral&fontColor=54f59a&fontSize=42&fontAlignY=40&desc=Umbral%20proxy%20re-encryption%20sidecar&descAlignY=64&descSize=16" alt="wevibe-umbral" width="100%" />

![Rust](https://img.shields.io/badge/Rust-000000?style=flat-square&logo=rust&logoColor=white)
[![status-alpha](https://img.shields.io/badge/status-alpha-ffc266?style=flat-square)](https://github.com/WeVibe-Network)
[![license-GPL--3.0](https://img.shields.io/badge/license-GPL--3.0-82aaff?style=flat-square)](LICENSE)
[![docs-wevibe-docs](https://img.shields.io/badge/docs-wevibe--docs-54f59a?style=flat-square)](https://github.com/WeVibe-Network/wevibe-docs)
[![%40WeVibe__Network](https://img.shields.io/badge/%40WeVibe__Network-0a0a0a?style=flat-square&logo=x&logoColor=white)](https://x.com/WeVibe_Network)

</div>

---

Umbral proxy re-encryption sidecar for secure member key delivery.

## Overview

`wevibe-umbral` is a Rust (`edition = 2021`) gRPC sidecar that implements proxy re-encryption (PRE) using `umbral-pre`.

It is published as both:

- a library crate: `wevibe_umbral`
- a service binary: `wevibe-umbral`

The sidecar re-encrypts a memory's wrapped data key from an org/epoch key to a member PRE public key **without ever accessing plaintext or the raw data key**.

## Role in the WeVibe Network

This service is the PRE boundary between hub orchestration and member-specific access.

- Default gRPC endpoint: `127.0.0.1:4460`
- Protocol definition: `proto/umbral/v1/sidecar.proto`
- Key RPCs:
  - `GenerateKeyPair` (epoch key generation)
  - `GenerateKFrags` (member kfrag generation/registration flow)
  - `ReEncrypt`
  - `DeleteKFrags`
  - `DeleteOrgKFrags`
  - `Health`

The hub owns kfrag lifecycle decisions and uses this sidecar for cryptographic operations. The Umbral workflow has been validated in integration tests, and hub internal PRE endpoints are active.

## Getting started

### Build

```bash
cargo build
```

Release build:

```bash
cargo build --release
```

### Run the sidecar

Start on the default local address:

```bash
cargo run -- serve
```

Or set a custom bind address:

```bash
cargo run -- serve --addr 0.0.0.0:4460
```

### Docker

A Dockerfile is included and exposes port `4460` for containerized sidecar deployments.

## Testing

Run tests:

```bash
cargo test
```

## Configuration

- Bind address is configurable via `serve --addr`.
- Logging follows standard Rust tracing configuration (`RUST_LOG`).

## Roadmap

See [ROADMAP.md](./ROADMAP.md) for current status and planned work.

## License

GPL-3.0. See [LICENSE](./LICENSE).

This crate is intentionally isolated as a dedicated sidecar to keep GPL-3.0 PRE implementation boundaries clean from Apache-licensed components in the broader stack.

## Links

- Docs: https://github.com/WeVibe-Network/wevibe-docs
- Organization: https://github.com/WeVibe-Network
- X: https://x.com/WeVibe_Network
