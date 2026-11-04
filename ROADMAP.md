# Roadmap

## v0.1 — Foundations (current)
- [x] Protocol spec v0-draft (`docs/spec.md`)
- [x] JSON Schemas for agent identity and attestations
- [x] Deterministic v0 scoring engine (pure Python, no deps)
- [x] Test suite for the scoring engine

## v0.2 — Real attestations
- [x] Signature verification (Ed25519 over canonicalized payloads)
- [x] Attestation log format (append-only, hash-chained)
- [x] CLI: `agentcred keygen | register | attest | query | verify | log`

## v0.3 — Registry API
- [x] REST API for register/attest/query/revoke/verify (`agentcred serve`, spec §9 — keys never leave clients)
- [x] Identity revocation flow (self-service via key possession, enforced in both directions)
- [x] Owner key rotation (v0.5: DID pinned, old key authorizes, key-timeline verification)
- [x] Client tooling for remote registries (v0.7: `RemoteRegistry` client + CLI `--url` mode, keys never leave the client)
- [ ] Sybil-resistance notes: rate-limited attestations, attester reputation bootstrapping

## v0.4 — Score maturity & the court system
- [x] Calibrate v0 formula against simulated agent populations (`tools/simulate.py`, enforced in CI)
- [x] Structured disputes: fault assignment, mutual/arbiter resolution, portable evidence bundles
- [x] Score decay over time (180-day evidence half-life in depth; quality metrics untouched)
- [x] False-accuser penalty for rejected disputes + `serial_false_accuser` flag
- [ ] Attester-weighting — open problem: peer-standing alone can't split collusion rings from honest clusters without outside anchors
- [x] Dispute rate limiting (duplicate + opener-cap + pile-on-cap, clock-free)
- [x] Deal protocol: mutual-signed deals, attestation-gated settlement, arbiter grace (v0.6, spec §11 — rail-agnostic; x402/AP2 rail binding remains future work)

## v1.0 — Protocol stabilization
- [ ] Cross-implementation test vectors
- [ ] Spec promoted from draft, versioned compatibility policy
- [ ] Reference deployment + public status page

## Non-goals (for now)
- A token / on-chain settlement — the protocol is neutral on transport and payment rails.
- Secret data collection — attestations reference events; they do not carry private payloads.
