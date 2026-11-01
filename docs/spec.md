# AgentCred Protocol — Specification (v0-draft)

> Status: draft. Everything here is stabilizing, not stable. Breaking changes
> will happen while the major version is 0.

## 1. Motivation

Agents increasingly act on behalf of principals: paying invoices, fulfilling
orders, negotiating with other agents. Every such interaction asks one question
the ecosystem cannot currently answer: **is this agent a reliable counterparty?**

AgentCred defines three primitives that together answer it:

1. **Agent Identity** — a persistent, owner-bound identifier.
2. **Attestations** — signed statements about an agent's behavior, issued by
   counterparties (other agents, platforms, or humans) that actually interacted
   with it.
3. **Trust Score** — a deterministic function of the attestation log, mapped to
   a band from **A** (highest) to **E** (unproven or risky).

Design stance: AgentCred is a *protocol and reference library*, not a company
database. Anyone can run a registry; scores are reproducible by anyone holding
the same attestation log.

## 2. Agent Identity

```json
{
  "did": "did:agentcred:01JAR3T9X8",
  "owner": "did:key:z6Mk... (human or organization)",
  "display_name": "invoice-bot@acme",
  "capabilities": ["payments.initiate", "invoices.parse"],
  "public_key": { "kty": "OKP", "crv": "Ed25519", "x": "..." },
  "created_at": "2026-11-01T00:00:00Z",
  "revoked": false,
  "version": 1
}
```

Rules:

- The **owner** is accountable for the agent's actions. An agent with no
  resolvable owner is unscoreable (band E, flag `no_owner`).
- **Revocation** is a one-way operation performed by the owner or registry
  policy. A revoked identity keeps its history but is excluded from new
  attestations.
- JSON Schema: `schema/agent-identity.schema.json`.

## 3. Attestations

```json
{
  "id": "att_01JAR3ZK7Q",
  "agent": "did:agentcred:01JAR3T9X8",
  "attester": "did:agentcred:01JAQ8W2R4",
  "type": "task_completed",
  "payload": { "task": "invoice-processing", "value_usd": 412.50 },
  "signed_at": "2026-11-01T12:04:11Z",
  "signature": "ed25519 detached JWS over canonicalized payload"
}
```

Attestation types (v0):

| type | meaning | score effect |
|---|---|---|
| `task_completed` | counterparty confirms a delegated task finished acceptably | positive |
| `payment_settled` | a payment the agent initiated or received settled as agreed | positive |
| `dispute_opened` | counterparty raised a dispute | negative |
| `dispute_resolved` | dispute closed (any outcome) | neutral, closes the dispute |
| `capability_verified` | counterparty observed the agent perform a capability | informational |

Rules:

- **Only counterparty attestations count.** An attestation where `attester == agent`
  is valid to store but has zero score weight.
- Attestations are **append-only**. Corrections are new attestations, not edits.
- Payloads must not carry secrets; they describe the event, not its contents.

## 4. Trust Score (v0)

Deterministic, reproducible, and intentionally boring. From the attestation log
of agent `a` at time `t`:

```
completed     = count(task_completed)
disputes_open = count(dispute_opened)
settled       = count(payment_settled)
volume_usd    = sum(payload.value_usd for payment_settled)
tenure_days   = t - first_attestation(a)

completion_rate = completed / max(1, completed + disputes_open)

score = 300                                    # floor: everyone starts unproven
      + 550 * completion_rate                  # did it finish what it started
      + min(50, settled)                       # track record volume
      + min(50, volume_usd / 1000)             # value track record (cap $50k)
      + min(50, tenure_days / 180)             # half-year of history maxes tenure
score = score * (1 - 0.1 * unclosed_disputes_factor)   # optional, see below
```

Bands (credit-bureau style):

| band | score | interpretation |
|---|---|---|
| A | ≥ 800 | proven, low-risk counterparty |
| B | 700–799 | solid history |
| C | 600–699 | moderate, limited history |
| D | 500–599 | weak; elevated dispute signal |
| E | < 500 or no attestations | unproven or risky |

v0 deliberately omits: score decay, attester weighting, dispute fault
assignment. These are roadmap items (`ROADMAP.md`), not current behavior.

## 5. Threat model (informal, v0)

- **Sybil agents** — fresh identities start at band E with the 300 floor; history
  cannot be bootstrapped without counterparty-signed events. Sybil *rings*
  (agents attesting each other) are the real open problem; v0 mitigation is
  attester weighting (v0.4) and registry-level attestation rate limits (v0.3).
- **Retaliation** — attesters may fear dispute retaliation. Mitigation (future):
  attester privacy via blind signatures. Out of scope for v0.
- **Key compromise** — owner key rotation is a v0.3 feature; until then,
  revocation is the only remedy.

## 6. Open questions

1. Should `dispute_opened` weight depend on the attester's own band?
2. How is "time" defined across registries — UTC attestation timestamps only?
3. Minimum viable sybil-resistance for a public registry: rate limits, proof of
   unique owner, or attestation stake?

## 7. Canonicalization & signatures (v0.2)

All signing and hashing operate on one byte-level canonical form so any
implementation produces identical bytes:

- UTF-8 encoded JSON
- object keys sorted lexicographically
- no insignificant whitespace (`,` and `:` separators only)
- non-ASCII characters preserved literally (`ensure_ascii=false`)

**Signing.** The signing input is the canonical form of the attestation's
*unsigned fields* — `id`, `agent`, `attester`, `type`, `payload`, `signed_at`.
The signature is Ed25519 (RFC 8032) over those bytes, stored detached in the
`signature` field as unpadded base64url.

**Keys.** Ed25519 JWKs (`kty: OKP`, `crv: Ed25519`). Public keys carry `x`;
private key files additionally carry the 32-byte seed in `d`. Agent DIDs are
content-derived: the first 12 hex characters of SHA-256 over the public key,
`did:agentcred:<hex>` — the same key always maps to the same DID.

**Verification.** A verifier resolves the attester's DID to its registered
public JWK, rebuilds the canonical unsigned form, and checks the signature.
Unsigned attestations are valid to store but must fail verification.

## 8. Attestation log (v0.2)

Registries keep attestations in an append-only JSONL log. Each record commits
to its predecessor:

```json
{"index": 0, "prev": "000...0", "entry": {...}, "hash": "..."}
```

- `prev` is the previous record's `hash`; the genesis record points at 64 zeroes.
- `hash` is SHA-256 over the canonical form of `{index, prev, entry}`.
- Records are strictly 0-indexed and append-only.

Because every record wraps its predecessor's hash, any edit, deletion, or
reordering anywhere in history breaks the chain and is detectable by anyone
re-walking the log. Note: the chain proves *integrity* (history unchanged),
not *truth* (attestations honest) — the latter is the scoring layer's job.
