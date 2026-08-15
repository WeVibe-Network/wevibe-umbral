# Contributing to WeVibe Network

Thank you for your interest in WeVibe Network.

**External contributions are currently paused during alpha development.**

This repository is private and under active development by the core team.
Pull requests from outside the organization will not be reviewed at
this time.

Once the network enters public testnet, this policy will change and
this document will be updated with contribution guidelines.

For questions about the project, see https://wevibe.network.

---

## Umbral WASM build — load-bearing facts

Umbral PRE runs in-process in `wevibe-mcp` from a WASM module built here and
committed into `wevibe-mcp/vendor/umbral-wasm`. There is no binary, no path,
and no environment variable. Six facts a future maintainer must not re-derive
the hard way:

1. **`crates/core` must always compile for `wasm32-unknown-unknown`.** A
   dependency that pulls threads/sockets/fs breaks the MCP for every user while
   the native build still passes. Guard it in CI with
   `cargo check -p wevibe-umbral-core --target wasm32-unknown-unknown`.
   `tonic`/`tokio`/`prost`/`dashmap` live in the ROOT crate, never in core.

2. **The `.wasm` is a COMMITTED build artifact.** Editing `crates/core` or
   `crates/wasm` does NOT change what the MCP runs until `scripts/build-wasm.sh`
   is re-run and `wevibe-mcp/vendor/umbral-wasm/` is committed. This is the one
   genuine staleness risk.

3. **`getrandom` needs an explicit JS backend on wasm32.** `umbral-pre` pulls
   `getrandom` 0.2 transitively; `wasm32` is unsupported by default. The
   `[target.'cfg(target_arch = "wasm32")'.dependencies]` block in
   `crates/core/Cargo.toml` is load-bearing — `encrypt`, `generate_kfrags`, and
   `SecretKey::random` (used in `deserialize_secret_key`) all need entropy. On
   `getrandom` 0.3 the feature renames to `wasm_js` and additionally needs
   `--cfg getrandom_backend="wasm_js"` in `RUSTFLAGS`.

4. **`vendor/umbral-wasm/package.json` must NEVER gain `"type":"module"`.**
   `wevibe-mcp` is ESM; the wasm-pack glue is CommonJS and only works because
   the vendored `package.json` omits a `type` field.

5. **Two toolchain traps.** Homebrew's `rustc` shadows rustup's and lacks the
   `wasm32` target — `build-wasm.sh` handles it, but a manual `wasm-pack` run
   won't. wasm-pack's bundled `wasm-opt` predates bulk-memory, so the flags in
   `crates/wasm/Cargo.toml` are required, not optional.

6. **Secrets must never transit argv again.** The old sidecar passed
   `--seed`/`--delegating-sk`/`--receiving-sk` as argv (readable via `ps`/proc).
   If any subprocess is ever reintroduced for crypto, pass secrets on stdin —
   never argv.