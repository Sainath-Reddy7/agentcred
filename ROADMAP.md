# Roadmap

## v0.1 — Foundations (current)
- [x] Protocol spec v0-draft (`docs/spec.md`)
- [x] JSON Schemas for agent identity and attestations
- [x] Deterministic v0 scoring engine (pure Python, no deps)
- [x] Test suite for the scoring engine

## v0.2 — Real attestations
- [x] Signature verification (Ed25519 over canonicalized payloads)
- [x] Attestation log format (append-only, hash-chained)
- [ ] CLI: `agentcred register | attest | query | verify`

## v0.3 — Registry API
- [ ] REST API for register/attest/query/revoke/dispute
- [ ] Owner key rotation + identity revocation flow
- [ ] Sybil-resistance notes: rate-limited attestations, attester reputation bootstrapping

## v0.4 — Score maturity
- [ ] Calibrate v0 formula against simulated agent populations
- [ ] Score decay over time (stale attestations count less)
- [ ] Optional attester-weighting (attestations from higher-banded counterparties count more)

## v1.0 — Protocol stabilization
- [ ] Cross-implementation test vectors
- [ ] Spec promoted from draft, versioned compatibility policy
- [ ] Reference deployment + public status page

## Non-goals (for now)
- A token / on-chain settlement — the protocol is neutral on transport and payment rails.
- Secret data collection — attestations reference events; they do not carry private payloads.
