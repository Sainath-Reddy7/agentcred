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
- [ ] REST API for register/attest/query/revoke/dispute
- [ ] Owner key rotation + identity revocation flow
- [ ] Sybil-resistance notes: rate-limited attestations, attester reputation bootstrapping

## v0.4 — Score maturity
- [x] Calibrate v0 formula against simulated agent populations (`tools/simulate.py`, enforced in CI)
- [ ] Score decay over time (stale attestations count less)
- [ ] Optional attester-weighting (attestations from higher-banded counterparties count more; targets 3+ agent collusion rings)

## v1.0 — Protocol stabilization
- [ ] Cross-implementation test vectors
- [ ] Spec promoted from draft, versioned compatibility policy
- [ ] Reference deployment + public status page

## Non-goals (for now)
- A token / on-chain settlement — the protocol is neutral on transport and payment rails.
- Secret data collection — attestations reference events; they do not carry private payloads.
