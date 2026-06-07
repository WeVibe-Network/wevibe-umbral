## Status

- Alpha-stage Umbral PRE sidecar with gRPC service and CLI in Rust.
- Core workflow is implemented: epoch keypair generation, member kfrag generation, re-encryption, and kfrag deletion paths.
- End-to-end PRE flow is validated in integration tests, and hub-side internal PRE endpoints are active.

## Near-term

- Tighten chain → hub → sidecar event coupling so member-removal events consistently trigger `DeleteKFrags`.
- Expand operational hardening around kfrag lifecycle observability and cleanup guarantees.

## Future

- Add re-encryption support for legacy memory formats that predate the current wrapped-key flow.
- Continue improving migration tooling and compatibility testing as encrypted-memory formats evolve.

## Design references

- WeVibe docs: https://github.com/WeVibe-Network/wevibe-docs
