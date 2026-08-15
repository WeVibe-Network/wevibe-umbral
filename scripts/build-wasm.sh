#!/usr/bin/env bash
#
# Build the Umbral WASM module and vendor it into wevibe-mcp.
#
# This is a MAINTAINER step, not a user step. End users never run it: the built
# artifact is committed to wevibe-mcp/vendor/umbral-wasm/ and ships inside the
# npm package. Nobody installing wevibe-mcp needs a Rust toolchain.
#
# Run this whenever anything under crates/core or crates/wasm changes, then
# commit the regenerated vendor/ directory in wevibe-mcp.
#
#   ./scripts/build-wasm.sh [dest]
#
# dest defaults to ../wevibe-mcp/vendor/umbral-wasm
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${1:-${REPO_ROOT}/../wevibe-mcp/vendor/umbral-wasm}"

# Homebrew's rustc commonly shadows rustup's on PATH and does NOT carry the
# wasm32 target, producing a confusing "target not found in sysroot" error.
# Prefer the rustup toolchain explicitly.
if [[ -x "${HOME}/.cargo/bin/rustc" ]]; then
  export PATH="${HOME}/.cargo/bin:${PATH}"
fi

command -v wasm-pack >/dev/null 2>&1 || {
  echo "error: wasm-pack not found. Install: cargo install wasm-pack" >&2
  exit 1
}

if ! rustup target list --installed 2>/dev/null | grep -qx wasm32-unknown-unknown; then
  echo "error: wasm32-unknown-unknown target missing." >&2
  echo "       Install: rustup target add wasm32-unknown-unknown" >&2
  exit 1
fi

echo "==> building wevibe-umbral-wasm (rustc $(rustc --version | awk '{print $2}'))"
cd "${REPO_ROOT}/crates/wasm"
wasm-pack build --target nodejs --release --out-dir pkg

echo "==> vendoring into ${DEST}"
mkdir -p "${DEST}"
# Deliberately NOT copying pkg/package.json's "files"/"main" wholesale — we
# keep the generated package.json because its ABSENCE of a "type" field is what
# keeps this directory CommonJS inside wevibe-mcp, which is "type":"module".
rm -f "${DEST}"/wevibe_umbral_wasm* "${DEST}"/package.json
cp pkg/wevibe_umbral_wasm_bg.wasm \
   pkg/wevibe_umbral_wasm.js \
   pkg/wevibe_umbral_wasm.d.ts \
   pkg/package.json \
   "${DEST}/"

WASM_BYTES=$(wc -c < "${DEST}/wevibe_umbral_wasm_bg.wasm" | tr -d ' ')
echo "==> done: ${WASM_BYTES} bytes ($((WASM_BYTES / 1024)) KB)"
echo
echo "Next: commit the regenerated vendor/umbral-wasm/ in wevibe-mcp, then run"
echo "      npm test in wevibe-mcp to verify cross-compatibility."
