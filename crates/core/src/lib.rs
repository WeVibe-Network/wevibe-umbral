//! Umbral PRE crypto core for WeVibe.
//!
//! This crate is the single source of truth for WeVibe's Umbral operations.
//! It is consumed by two builds that must never diverge:
//!
//!   * `wevibe-umbral`      — the native binary + gRPC service
//!   * `wevibe-umbral-wasm` — the WASM module shipped inside `wevibe-mcp`
//!
//! INVARIANT: this crate must always compile for `wasm32-unknown-unknown`.
//! Adding a dependency that pulls in threads, sockets or the filesystem
//! breaks the MCP for every user. `make verify` enforces this.

pub mod crypto;
pub mod ops;
