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
- **Revocation** is one-way and self-service: possession of the identity's
  current private key is the authority to revoke it (`Registry.revoke`, CLI
  `agentcred revoke --key`). A revoked identity keeps its history but is
  excluded from new attestations **in both directions** — as subject and as
  attester. The registry records `revoked_at` and bumps `version`.
- **Key rotation (v0.5)** replaces an identity's key without changing its
  DID — the DID names the identity, not the key. The rotation is a
  `key.rotated` chain record signed by the **old** key and carrying both
  the old and new public JWKs, so the record stays verifiable long after
  the registry has forgotten the old key. Verification walks a **key
  timeline**: every historical record is checked against the key that was
  valid at its chain position. A key already owned by another identity
  cannot be rotated onto, and one key can never register two identities.
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

## 4. Trust Score (v0.4)

Deterministic, reproducible, and calibrated: the shape below is validated
against simulated agent populations (`tools/simulate.py`), which runs in CI
and fails the build if a trust invariant breaks. From the attestation log
of agent `a` at time `t`:

```
completed     = count(task_completed)
settled       = count(payment_settled)
disputes_open = count(dispute_opened)
volume_usd    = sum(payload.value_usd for payment_settled)
tenure_days   = t - first_attestation(a)

interactions  = completed + settled
distinct      = count(distinct counterparty attesters)
total_disputes = disputes_open + structured_open + disputes_upheld
                 (rejected/settled disputes are lifted — see §10)

age_weight(a) = 0.5 ** (age_days(a) / 180)   # evidence half-life: 180 days
effective     = sum(age_weight over task/payment attestations)

reliability = interactions / max(1, interactions + 2 * total_disputes)
depth       = min(1, effective / 20) * min(1, distinct / 3)
value       = min(1, volume_usd / 20000)
tenure      = min(1, tenure_days / 180)

score = 300                                        # floor: everyone starts unproven
      + 350 * reliability * depth                  # behavior, paid out only as evidence accumulates
      + 200 * depth                                # track record: decayed volume x attester diversity
      + 100 * value                                # settled value
      + 50  * tenure                               # survived time
      - 300 * min(1, total_disputes / max(1, interactions))
      - 100 * min(1, false_accusations / 3)        # serial false accusers (§10)
score = clamp(score, 300, 900)
```

Design intent, each addressing a v0.2 miscalibration:

- **Thin histories stay provisional.** Reliability pays out only in
  proportion to depth: one clean interaction tops out near 310 (band E).
  v0.2 handed a single success 550 points and band A.
- **Payments are reliability.** `payment_settled` feeds `reliability`, so
  clean payment-only histories progress instead of hugging the floor.
- **Disputes bite twice** — double-weighted inside `reliability` and
  subtracted again as explicit dispute load.
- **Attester diversity gates depth** (the distinct-creditor principle):
  history from a single counterparty caps depth at one third, containing
  two-agent sybil rings at band E. This is containment, not a solution —
  rings of three or more colluding attesters still score; attester
  weighting is the v0.4 follow-up.
- **Evidence decays; quality doesn't.** Interaction counts decay with a
  180-day half-life (`effective` feeds depth) while reliability and
  dispute load use raw history. A two-year-old success still proves
  honesty — it just proves less of it. Dormant agents slide down the
  bands; agents that keep transacting hold theirs.

Enforced calibration invariants (see `tools/simulate.py`): fresh and
one-shot agents hold E; established diverse agents reach A; a 50% dispute
rate lands D; single-attester histories stay under 500; a one-year-stale
history drops below 600 while the same history kept active holds 700+;
serial false accusers are flagged and demoted.

Remaining limits, deliberate and documented: attester weighting is an
open problem — pure peer-standing cannot distinguish a 3-agent collusion
ring from an honest cluster without outside anchors (§6); raw v0.2
`dispute_opened` attestations still count 1x alongside structured
disputes.

Bands (credit-bureau style):

| band | score | interpretation |
|---|---|---|
| A | ≥ 800 | proven, low-risk counterparty |
| B | 700–799 | solid history |
| C | 600–699 | moderate, limited history |
| D | 500–599 | weak; elevated dispute signal |
| E | < 500 or no attestations | unproven or risky |

v0 deliberately omits: attester weighting (open problem, §6) and
dispute rate limiting. See `ROADMAP.md`.

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
4. Should canonicalization adopt a formal profile (e.g., RFC 8785 JCS) so
   number formatting is byte-identical across every language?

## 7. Canonicalization & signatures (v0.2)

All signing and hashing operate on one byte-level canonical form so any
implementation produces identical bytes:

- UTF-8 encoded JSON
- object keys sorted lexicographically
- no insignificant whitespace (`,` and `:` separators only)
- non-ASCII characters preserved literally (`ensure_ascii=false`)
- numbers as shortest-roundtrip IEEE-754 doubles (Python `json` and
  ECMAScript `JSON.stringify` agree; exotic float formatting may not — see
  open questions)

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

## 9. Registry HTTP API (v0.3)

`agentcred serve` exposes a registry over JSON/HTTP (FastAPI reference
implementation). One rule above all: **private keys never leave clients.**
Clients sign locally per §7 and submit; the server verifies against
registered public keys and commits to the §8 log.

| endpoint | effect | errors |
|---|---|---|
| `GET /agents` | list registered identities | — |
| `POST /agents` | register from a public JWK → identity (201) | 400 malformed, 409 duplicate |
| `GET /agents/{did}` | identity + trust score report | 404 unknown |
| `GET /agents/{did}/attestations` | raw attestation history | 404 unknown |
| `GET /attestations/{id}` | one committed attestation (clients resolve dispute targets with it) | 404 unknown |
| `POST /attestations` | submit a fully-signed attestation | 400 invalid/unsigned/bad signature/future-dated, 404 unknown party, 409 revoked party |
| `GET /disputes` | list disputes (optional `?agent=did` filter) | — |
| `POST /disputes` | open a dispute over an attestation | 400 invalid/bad signature/rate-limited, 404 unknown party, 409 revoked |
| `POST /disputes/{id}/resolve` | resolve (mutual or arbiter signatures) | 400 bad signature/coverage, 404 unknown, 409 already resolved |
| `GET /disputes/{id}` | dispute view | 404 unknown |
| `GET /disputes/{id}/evidence` | portable evidence bundle | 404 unknown |
| `POST /agents/{did}/revoke` | revoke; body is a signature over `canonical({"action": "revoke", "agent": did})` | 400 bad signature, 404 unknown, 409 already revoked |
| `POST /agents/{did}/rotate` | rotate the identity's key; body carries `old_public_jwk`, `new_public_jwk`, `rotated_at`, and a signature by the current key over the canonical record | 400 bad signature/mismatch, 404 unknown, 409 revoked/key-in-use |
| `GET /verify` | chain + signature audit report | — |
| `GET /health` | liveness + version | — |

Server-side rules for submitted attestations:

- The attester and subject must both be registered and unrevoked.
- The signature must verify under the attester's *registered* public key —
  key substitution in the submitted body is irrelevant because the registry
  ignores any key material it did not register.
- `signed_at` must be ISO-8601 and no more than 5 minutes in the future
  (clock-skew tolerance). Back-dating is permitted by design: attestations
  describe past events.
- The registry stamps its own time in the local CLI path; in the API path
  the client's `signed_at` is authoritative within the tolerance above.

Revocation over HTTP proves authority the same way everything else does —
with a signature — since possession of the private key is the only
authority the protocol recognizes (until v0.3 owner-key rotation).

**Not provided yet** (reference deployment, not production): authentication,
rate limiting, request signing, multi-tenant state. Sybil-resistance
measures are the open v0.3 roadmap item.

**Reference client (v0.7).** `agentcred.client.RemoteRegistry` mirrors the
local Registry surface over this API — register, attest, query, verify,
disputes, evidence, deals, rotation, revocation — signing locally so keys
never leave the client process. The CLI drives it with the global
`--url` flag: `agentcred --url https://registry.example attest …`.

## 10. Disputes & evidence bundles (v0.4)

The court system. The chain (§8) gains record kinds: `attestation` (the
default, including all pre-v0.4 records), `dispute.opened`,
`dispute.resolved`, and `key.rotated` (§2).

### Opening

A dispute targets **one specific attestation**. Core fields — the exact
bytes the opener signs (canonical form, §7):

```
{kind: "dispute.opened", id, target, agent, opened_by, reason, opened_at, arbiter}
```

- `agent` (the disputed party) must equal the target attestation's agent.
- `opened_at` must be ISO-8601 UTC, no further in the future than 5
  minutes (clock-skew tolerance, same rule as attestations); the same
  applies to `resolved_at` on resolutions, which must be present.
- `arbiter` is optional: a registered, unrevoked agent who is not the
  disputed party. Setting it enables arbiter mode.

### Resolution

Core fields, with `signatures` paired 1:1 with `resolved_by`:

```
{kind: "dispute.resolved", dispute, outcome, resolved_by: [did, ...], resolved_at}
```

- **Mutual mode** (no arbiter): both the opener and the disputed agent sign.
- **Arbiter mode**: the nominated arbiter's signature alone suffices.
- Outcomes: `upheld` (fault against the disputed agent), `rejected` (the
  accusation failed), `settled` (mutual walk-away, no fault).

### Fault-aware scoring

Upheld and still-open disputes count against the agent (§4); rejected and
settled ones are lifted — a false accusation costs the accused nothing.
Referencing a specific attestation is what makes fault assignment
possible at all. The price of a false accusation lands on the *opener*:
each rejected dispute counts toward `false_accusations`, costing 100
points per third (max −100) and a `serial_false_accuser` flag from two
onward. One mistake is free; a pattern is not.

### Evidence bundles

`agentcred evidence --dispute dsp_x` exports an
`agentcred/evidence-bundle@1` document: the signed records (opening,
resolution, target attestation) plus the public identities needed to
verify every signature offline (`agentcred verify-bundle`). Any third
party — arbiter, platform, regulator — can check the document with no
registry access. The verifier **binds the bundle to its target**: the
carried attestation must be exactly the one the dispute names, so a
swapped-in record (even one with its own valid hash and signature) fails
with `target_mismatch`. Subset bundles prove record integrity and
authenticity; chain *membership* requires the full log, so bundles carry
`meta.head` to anchor against a live registry.

### Rate limits

Open disputes count provisionally against the accused, so mass-opening
must not be free. Three clock-free rules, enforced at commit:

- one open dispute per (opener, target) — no duplicate piling by the
  same party;
- at most **5 open disputes per opener** at a time (resolving frees
  capacity);
- at most **3 open disputes per attestation** across all openers.

### Honest limits

No escrow/settlement integration (x402/AP2 rails are a separate roadmap
item); limits are per-registry, not cross-registry.

## 11. Deals & settlement (v0.6)

The commerce layer: rail-agnostic escrow semantics. A deal is a
mutually-signed agreement; settlement commits only when its condition is
*proven on-chain* by a signed attestation. Any payment rail (x402, AP2,
cards, banks) can bind funds to these records later — the registry holds
proof, not money.

### Opening

`deal.opened` — signed by BOTH payer and payee over the canonical core:

```
{kind, id (deal_*), payer, payee, amount_usd, terms, condition_type,
 deadline (ISO-8601 or null), arbiter (did or null), opened_at}
```

- `condition_type` ∈ {task_completed, payment_settled, capability_verified}.
- `deadline` must be after `opened_at`. The registry runs no timers —
  expiry is derived at read time (`status: expired`).
- `arbiter`, if set, must be registered, unrevoked, and not a party.

### Settlement — attestation-gated release

`deal.settled` — signed by the payer (or, past the deadline, only the
arbiter). It cites a `settlement` attestation id, and the registry refuses
to commit unless that attestation:

- exists on the chain, and was signed after the deal opened;
- is about the **payee**, of the agreed **condition_type**;
- is signed by the **payer or the arbiter**;
- is **bound to the deal** via `payload.deal == deal_id`.

A favorable attestation about anything else — another agent, another deal,
the wrong type, or self-attested — settles nothing. The binding via
`payload.deal` is what turns a generic praise into escrow evidence.

### Cancellation

`deal.cancelled` — mutual (payer + payee), no fault assigned. The refund
path; contested failures belong in the dispute system (§10), where fault
is assigned.

### Interaction with the rest of the protocol

Scoring is deliberately unchanged: the condition attestation already
scores as a normal interaction. Deals add provable settlement terms, not
bonus points. Deal records verify on the chain like every other record
(opened: two party signatures; settled: signer + settlement-reference
structural check; cancelled: two party signatures).

**Contested settlements (v0.7.2).** The court and the deal layer are
connected: if a dispute over a settled deal's condition attestation is
later **upheld**, the deal view carries `contested: true`. The chain is
immutable, so the settlement record stands — but any consumer reading
the deal is warned that its evidence was overturned in court. A rejected
or settled dispute contests nothing.

### Honest limits

The registry proves conditions were met; it does not move money, and a
settled deal says nothing about which rail transferred funds — rail
binding (x402/AP2) is future work. Deal-opening is not rate-limited (a
deal needs the counterparty's signature, so spam requires cooperation).
