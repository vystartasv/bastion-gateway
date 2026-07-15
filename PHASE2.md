# Phase 2 — Hosted Evidence Tier (not built)

Scope for when hosted/multi-tenant evidence tier is started:

- Managed retention (long-term WORM storage)
- Multi-tenant evidence portal
- Attestation/export SLAs
- Phone-push approval integration
- Pluggable storage backend (local disk → S3/compatible)
- Externalised key management (HSM/KMS)

## v1 interface observances (already built in evidence/storage.go)

- Storage backend is behind an interface: `evidence.Storage`
- Key management behind `evidence.Signer`
- Both proven by swappable in-memory test doubles:
  - `MemoryStorage` passes all ledger tests without modification
  - `TestSigner` passes all ledger tests without modification
