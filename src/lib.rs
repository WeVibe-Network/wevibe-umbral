pub mod store;
pub mod generated;
pub mod service;
pub mod cli;

/// Re-exported from `wevibe-umbral-core` so existing paths
/// (`wevibe_umbral::crypto::…`) keep resolving. The implementation moved so
/// the WASM build in `crates/wasm` can share it — see crates/core/src/lib.rs.
pub use wevibe_umbral_core::crypto;

pub use service::UmbralSidecarService;
