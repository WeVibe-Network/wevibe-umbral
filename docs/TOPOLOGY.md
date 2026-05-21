# wevibe-umbral Topology

## Purpose

`wevibe-umbral` is a standalone Rust binary that wraps the GPL-3.0 `umbral-pre` crate behind two stable interfaces:

- gRPC server mode (`serve`) for hub-side PRE operations
- CLI subcommands (`encrypt`, `decrypt-reencrypted`) for client-side PRE operations invoked by `wevibe-mcp`

It provides Proxy Re-Encryption (PRE) operations for the WeVibe Network retrieval architecture while preserving the GPL-3.0 / Apache-2.0 license boundary. Apache-2.0 services and tools interact with the sidecar as a separate process and never link `umbral-pre` directly.

**License:** GPL-3.0-only
**Port:** 127.0.0.1:4460 (localhost-only, no TLS)

## File Inventory

```
WeVibe-Network/wevibe-umbral/
├── Cargo.toml           # Dependencies: umbral-pre 0.11.0, tonic 0.14.5, prost, tokio, dashmap, clap
├── build.rs             # tonic-prost-build proto compilation
├── proto/
│   └── umbral/v1/
│       └── sidecar.proto  # gRPC service definition (6 RPCs)
├── src/
│   ├── main.rs          # Clap subcommand entry point (serve/encrypt/decrypt-reencrypted)
│   ├── lib.rs           # Module declarations + public exports
│   ├── generated.rs     # Pre-generated tonic/prost proto stubs
│   ├── cli.rs           # CLI crypto implementation + JSON contract output
│   ├── crypto.rs        # Shared Umbral ser/deser helpers used by service and CLI
│   ├── service.rs       # UmbralSidecar trait implementation (all 6 RPC handlers)
│   └── store.rs         # DashMap-based in-memory kfrag store
└── docs/
    └── TOPOLOGY.md      # This file
```

## CLI Contract

The binary exposes three runtime modes:

1. `serve` - starts gRPC server on `127.0.0.1:4460`
2. `encrypt` - encrypts plaintext under epoch public key
3. `decrypt-reencrypted` - decrypts re-encrypted ciphertext using cfrags

No subcommand defaults to `serve` mode for backward compatibility.

### `encrypt`

Input:

```bash
wevibe-umbral encrypt \
  --epoch-pk <hex> \
  --plaintext <hex>
```

Output (stdout JSON):

```json
{"capsule":"<hex>","ciphertext":"<hex>"}
```

### `decrypt-reencrypted`

Input:

```bash
wevibe-umbral decrypt-reencrypted \
  --capsule <hex> \
  --cfrags <hex[,hex...]> \
  --ciphertext <hex> \
  --receiving-sk <hex> \
  --delegating-pk <hex>
```

Output (stdout JSON):

```json
{"plaintext":"<hex>"}
```

Error behavior:

- Invalid input or cryptographic failure emits JSON to stderr:

```json
{"error":"<message>"}
```

- Process exits non-zero.

## gRPC Service Contract

**Package:** `umbral.v1`
**Service:** `UmbralSidecar`

| RPC | Request | Response | Description |
|-----|---------|----------|-------------|
| `GenerateKeyPair` | `GenerateKeyPairRequest` (empty) | `GenerateKeyPairResponse` (sk, pk) | Generates random Umbral epoch keypair |
| `GenerateKFrags` | `GenerateKFragsRequest` (org_id, epoch_id, delegating_sk, receiving_pk, signer_sk, verifying_pk) | `GenerateKFragsResponse` (kfrag) | Generates and stores kfrag for a member |
| `ReEncrypt` | `ReEncryptRequest` (org_id, epoch_id, member_pk, capsule) | `ReEncryptResponse` (cfrag) | Applies stored kfrag to capsule |
| `DeleteKFrags` | `DeleteKFragsRequest` (org_id, member_pk) | `DeleteKFragsResponse` (deleted_count) | Deletes all kfrags for a member across all epochs |
| `DeleteOrgKFrags` | `DeleteOrgKFragsRequest` (org_id) | `DeleteOrgKFragsResponse` (deleted_count) | Deletes ALL kfrags for an org |
| `Health` | `HealthRequest` (empty) | `HealthResponse` (healthy, kfrag_count, umbral_version) | Returns sidecar health status |

## Serialization Format

All byte fields use MessagePack serialization via `umbral-pre`'s `DefaultSerialize`/`DefaultDeserialize` traits:
- **SecretKey:** 32 bytes big-endian (BE) scalar
- **PublicKey:** 33 bytes compressed secp256k1 (0x02/0x03 prefix + X coordinate)
- **Capsule:** MessagePack-encoded `Capsule`
- **VerifiedKeyFrag / VerifiedCapsuleFrag:** MessagePack-encoded

## KFrag Storage

Key: `(org_id, epoch_id, member_pk_hex)` → serialized kfrag bytes

Storage is in-memory only (Phase 1). Phase 2 will add encrypted-at-rest persistence.

**Storage key derivation:**
- `member_pk_hex` = hex-encoded 33-byte compressed public key
- Example: `org_id="org_abc123", epoch_id=5, member_pk_hex="02a1b2c3..."`

**DeleteKFrags behavior:** Deletes all entries matching `(org_id, *, member_pk_hex)`. Idempotent — returns 0 if no entries found.

## Dependencies

| Dependency | Version | License | Role |
|-----------|---------|---------|------|
| `umbral-pre` | 0.11 | GPL-3.0 | PRE cryptography (isolated) |
| `clap` | 4 | MIT/Apache-2.0 | CLI subcommand parsing |
| `serde_json` | 1 | MIT/Apache-2.0 | Stable JSON CLI output |
| `tonic` | 0.14.5 | MIT | gRPC server framework |
| `prost` | 0.14 | MIT | Protocol buffer codec |
| `tokio` | 1 | MIT | Async runtime |
| `dashmap` | 6 | MIT | Concurrent HashMap for kfrag store |
| `tracing` | 0.1 | MIT | Structured logging |
| `hex` | 0.4 | MIT | Hex encoding for storage keys |

## Deployment

The sidecar is a standalone binary. In server mode it is started before wevibe-hub; in CLI mode it is executed on-demand by wevibe-mcp.

**Server startup:**
```bash
./wevibe-umbral serve
# or: ./wevibe-umbral
# Logs: "Umbral sidecar listening on 127.0.0.1:4460"
```

**CLI startup examples:**
```bash
./wevibe-umbral encrypt --epoch-pk <hex> --plaintext <hex>
./wevibe-umbral decrypt-reencrypted --capsule <hex> --cfrags <hex[,hex...]> --ciphertext <hex> --receiving-sk <hex> --delegating-pk <hex>
```

**Health check:**
```bash
grpcurl -plaintext 127.0.0.1:4460 umbral.v1.UmbralSidecar/Health
```

## Cross-Module Relationships

- **Hub → Sidecar:** gRPC calls on `127.0.0.1:4460`. Sidecar never initiates connections.
- **wevibe-mcp → Sidecar:** subprocess CLI invocation (`encrypt`, `decrypt-reencrypted`) using hex args and JSON stdout/stderr.
- **wevibe-guard pattern parity:** same process-boundary model (external GPL boundary binary called by Apache-2.0 consumer).
- **Sidecar → Hub:** None. Hub owns retrieval flow; sidecar is passive.
- **Chain → Hub → Sidecar:** MemberRemoved chain event triggers hub → sidecar `DeleteKFrags` RPC.

## Phase 1 Limitations

- No encrypted-at-rest persistence (in-memory only, lost on restart)
- No kfrag backup/audit export
- SecretKey deserialization uses `SecretKeyFactory` workaround (CO-216-F4 verified sound in CO-217)
- No authentication on gRPC connection (localhost-only assumed)
- No metrics/prometheus endpoint

## Testing (CO-220)

**Test file:** `tests/integration.rs`

**Store tests (6):**
| Test | Description |
|------|-------------|
| `test_store_and_retrieve_kfrag` | Store kfrag under (org_id, epoch_id, member_pk_hex), retrieve, verify match |
| `test_store_multiple_members_same_org` | 3 members same org/epoch, verify no cross-contamination |
| `test_delete_kfrags_by_member` | Delete by member removes all epoch entries, other members untouched |
| `test_delete_org_kfrags` | Delete org removes all members/epoch entries, other orgs untouched |
| `test_overwrite_existing_kfrag` | Overwrite with new value replaces old |
| `test_retrieve_nonexistent_kfrag` | Nonexistent returns None |

**Crypto verification tests (9):**
| Test | Description |
|------|-------------|
| `test_factory_workaround_can_sign_and_verify` | Factory workaround keys sign correctly |
| `test_secretkey_factory_workaround_produces_valid_signing_key` | Seeds produce valid signing keys |
| `test_encrypt_reencrypt_decrypt_flow` | Full Umbral workflow succeeds with factory workaround keys |
| `test_cli_unit_encrypt_decrypt_roundtrip` | Unit-level CLI logic roundtrip (`encrypt_hex` -> `decrypt_reencrypted_hex`) |
| `test_cli_subprocess_encrypt_produces_json` | `encrypt` subprocess emits contract JSON with valid hex payloads |
| `test_cli_subprocess_decrypt_reencrypted_produces_json` | `decrypt-reencrypted` subprocess decrypts to original plaintext |
| `test_cli_subprocess_encrypt_invalid_hex_errors` | Invalid encrypt hex input returns non-zero + JSON stderr error |
| `test_cli_subprocess_decrypt_empty_cfrags_errors` | Empty cfrags returns non-zero + JSON stderr error |
| `test_cli_subprocess_decrypt_wrong_key_errors` | Wrong receiving key returns non-zero + JSON stderr error |

**SecretKey workaround verdict (CO-217):** VERIFIED SOUND — workaround produces keys that are cryptographically valid for signing/verification and support full encrypt→reencrypt→decrypt flow. True round-tripping (original key ≠ restored key from same bytes) is NOT supported — would require `SecretKey` to implement serde `Deserialize` (not available in umbral-pre 0.11.0).
