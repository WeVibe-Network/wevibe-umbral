<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:02100a,100:2fe07a&height=160&section=header&text=wevibe-umbral&fontColor=54f59a&fontSize=42&fontAlignY=40&desc=Umbral%20proxy%20re-encryption%20sidecar&descAlignY=64&descSize=16" alt="wevibe-umbral" width="100%" />

![Rust](https://img.shields.io/badge/Rust-000000?style=flat-square&logo=rust&logoColor=white)
[![status-alpha](https://img.shields.io/badge/status-alpha-ffc266?style=flat-square)](https://github.com/WeVibe-Network)
[![license-GPL--3.0](https://img.shields.io/badge/license-GPL--3.0-82aaff?style=flat-square)](LICENSE)
[![docs-wevibe-docs](https://img.shields.io/badge/docs-wevibe--docs-54f59a?style=flat-square)](https://github.com/WeVibe-Network/wevibe-docs)
[![%40WeVibe__Network](https://img.shields.io/badge/%40WeVibe__Network-0a0a0a?style=flat-square&logo=x&logoColor=white)](https://x.com/WeVibe_Network)

</div>

---

Umbral proxy re-encryption sidecar: re-encrypts each encrypted memory's data key from the organization's delegating key to the member's receiving key, so the coordinating hub can route encrypted memory between principals without ever being able to read it.

## Overview

`wevibe-umbral` is a Rust gRPC sidecar (`tonic` 0.14.5, `umbral-pre` 0.11.0) that performs Umbral proxy re-encryption (PRE). It takes a memory's *capsule* — the Umbral-wrapped data encryption key (DEK) — and re-encrypts it from the organization's epoch delegating key to the requesting member's receiving key. The gRPC service path never touches plaintext, the ciphertext body, or the raw DEK.

This is how WeVibe delivers attributed, encrypted memory across a trust boundary: the confidentiality guarantee between the hub and each member is a concrete cryptographic property of the construction, not a trust promise.

Published as a library crate (`wevibe_umbral`) and a service binary (`wevibe-umbral`).

## What it does

The gRPC service (package `umbral.v1`, service `UmbralSidecar`) exposes exactly five RPCs:

| RPC | Purpose |
| --- | --- |
| `StoreKFrag` | Store a leader-minted kfrag for `(org_id, member_pk)`. |
| `ReEncrypt` | Apply the stored kfrag to a capsule, producing a cfrag. Called by the hub during memory retrieval. |
| `DeleteKFrags` | Delete the member's kfrag on member removal. Idempotent. |
| `DeleteOrgKFrags` | Delete every kfrag for an org on dissolution. |
| `Health` | Liveness, stored-kfrag count, umbral version. |

Kfrags are minted leader-side — epoch keypair and kfrag generation exist only as CLI/WASM ops (threshold 1-of-1) — and are delivered to the sidecar via `StoreKFrag`. At retrieval, `ReEncryptRequest` carries only `{org_id, member_pk, capsule}`; the handler deserializes the stored kfrag and capsule and calls `umbral_pre::reencrypt` (`src/service.rs`). The response is a cfrag: a re-encrypted fragment the member's device combines with its own secret key to recover the DEK. Byte fields on the wire are MessagePack-serialized Umbral types.

Client-side crypto is not part of this service: the same binary's CLI subcommands, and the WASM module vendored into `wevibe-mcp`, expose encrypt/decrypt for use on the member's own device with the member's own secret key. The gRPC service has no plaintext access; those tooling paths do, locally.

## The confidentiality boundary

The hub can compute the re-encryption step — capsule times kfrag:

```
cfrag = rk · (E + V) = (a · b⁻¹) · (E + V)
```

but recovering the DEK requires

```
K = KDF(a · (E + V))
```

which requires the member's secret scalar `b`. The hub is structurally never given `b` — no configuration, key rotation, or privileged mode grants it. Decryption happens only on the member's device, which multiplies the cfrag by its own `b`. Think of a postal sorting office that re-addresses a sealed envelope without any way to open it. This is geometry, not policy (WHITEPAPER §4.5, "Hub Confidentiality: Why the Hub Cannot Decrypt").

What this claims, and what it does not:

- **True:** the hub cannot decrypt memory content.
- **Not claimed:** the hub learns nothing. For retrieval the hub holds clean float32 embeddings plus plaintext label metadata — a disclosed, lossy, realistically-invertible *semantic shadow* of the corpus — with operational (not cryptographic) mitigations. WeVibe makes no claim of a zero-knowledge index or a content-confidential hub.

## No epoch rotation

The key model has no epoch dimension. The store is keyed by `(org_id, member_pk)` with exactly one kfrag per member; epoch rotation was removed (`0089e92` "single kfrag per member"). The epoch key is a fixed delegating keypair derived once from the organization seed.

## Proto & codegen

- Authoritative proto: [`proto/umbral/v1/sidecar.proto`](proto/umbral/v1/sidecar.proto)
- Byte-identical mirror on the Go side: `wevibe-server/wevibe-hub/internal/umbral/umbralpb/sidecar.proto`, with generated `sidecar.pb.go` / `sidecar_grpc.pb.go`.
- Go codegen: `make proto-gen-umbral` in `wevibe-meta` — pinned image `bufbuild/buf:1.34.0`, plugins protoc-gen-go v1.36.11 + protoc-gen-go-grpc v1.6.2; source is this repo's proto, output is the hub-nested `umbralpb/`.
- Rust stubs are checked in at `src/generated.rs`; `build.rs` is a no-op.

## Relationship to wevibe-hub

`wevibe-hub` (the Go module nested in `wevibe-server`) consumes the sidecar as a relay:

- relays `ReEncrypt` requests during memory retrieval,
- delivers leader-supplied kfrags via `StoreKFrag`,
- deletes a member's kfrags on removal (forward secrecy by kfrag purge) and an org's kfrags on dissolution.

Wire: plaintext gRPC to `127.0.0.1:4460` (default) or `wevibe-umbral:4460` on compose DNS. On compose the sidecar is container-only — no host port mapping. Content confidentiality comes from the PRE boundary above, not from the transport.

## Layout

- `crates/core` — all Umbral crypto (`ops.rs`, `crypto.rs`).
- `crates/wasm` — WASM bindings; excluded from the workspace, vendored into `wevibe-mcp` as `vendor/umbral-wasm`.
- `src/` — binary + lib: `main.rs`, `service.rs`, `store.rs`, `cli.rs`, `generated.rs`.
- Key deps: `umbral-pre` 0.11.0, `tonic` 0.14.5, `prost` 0.14, `tokio`, `clap`, `dashmap`.

## Build & run

```bash
cargo build --release
./target/release/wevibe-umbral serve --addr 127.0.0.1:4460
```

The Dockerfile builds the release binary and exposes `4460`.

## Configuration

| Setting | Default | Notes |
| --- | --- | --- |
| `serve --addr` | `127.0.0.1:4460` | Bind address. |
| `WEVIBE_UMBRAL_KFRAG_STORE` | `/data/kfrags.json` | Kfrag store path; writes are atomic (temp + rename) with fsync, file mode `0600`. |
| `RUST_LOG` | — | Standard tracing filter. Every gRPC method and store op logs entry + outcome; crypto inputs appear only as fingerprints and sizes. |

## Testing

```bash
cargo test
```

Integration tests cover the store → re-encrypt → decrypt roundtrip (`tests/integration.rs`, `tests/epoch_kfrag.rs`, `tests/roundtrip.rs`).

## Status

Alpha / pre-production. Interfaces and semantics may change. See [ROADMAP.md](ROADMAP.md).

## License

GPL-3.0 — see [LICENSE](LICENSE). The sidecar is deliberately isolated as its own process and crate to keep the GPL-3.0 PRE implementation on its side of the license boundary, separate from the Apache-licensed components in the rest of the stack.

## Links

- Docs: https://github.com/WeVibe-Network/wevibe-docs
- Organization: https://github.com/WeVibe-Network
- X: https://x.com/WeVibe_Network
