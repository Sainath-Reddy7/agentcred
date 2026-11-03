# AgentCred

<p align="center">
  <a href="https://github.com/Sainath-Reddy7/agentcred/actions/workflows/ci.yml"><img src="https://github.com/Sainath-Reddy7/agentcred/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/status-research%20%26%20prototype-orange" alt="status">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="python">
  <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="license">
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="prs">
  <img src="https://img.shields.io/github/stars/Sainath-Reddy7/agentcred" alt="stars">
</p>

> **A credit bureau for AI agents.** Identity, attestations, and trust scores for the agentic economy.

## The problem

AI agents are starting to transact on behalf of people and businesses — paying invoices,
fulfilling orders, negotiating deals. The missing primitive is trust infrastructure:

- A merchant accepting an agent's payment has no way to ask, *"does this agent pay?"*
- A platform delegating a task can't ask, *"does this agent finish what it starts?"*
- An agent hiring another agent has no counterparty history to check.

Humans solved this with credit bureaus. The agent economy has nothing yet. **AgentCred
is an open protocol + reference implementation for agent identity, third-party
attestations, and derived trust scores.**

## How it works

```
┌──────────────┐    register     ┌──────────────┐
│  AI Agent    │ ──────────────▶ │   Registry   │  did:agentcred:<id>
│  (owned by   │                 │  (identity)  │  owner, capabilities, public key
│   human/org) │ ◀────────────── │              │
└──────────────┘                 └──────────────┘
       │                                ▲
       │ transacts with counterparties  │ signed attestations
       ▼                                │
┌──────────────┐   submit events  ┌──────────────┐   query   ┌──────────────┐
│ Counterparty │ ───────────────▶ │ Attestation  │ ────────▶ │ Trust Score  │
│ (agent/platform/human)          │    Log       │           │  (band A–E)  │
└──────────────┘                  └──────────────┘           └──────────────┘
```

1. **Register** — an agent gets a persistent identity (`did:agentcred:<id>`) binding it
   to a responsible owner, a capability set, and a public key.
2. **Attest** — counterparties record signed events: `task_completed`,
   `payment_settled`, `dispute_opened`, `capability_verified`. Self-attestations
   don't count; only counterparty-signed events do.
3. **Score** — a deterministic scoring function derives metrics (completion rate,
   dispute ratio, settled volume, tenure) and maps them to a trust band **A–E**.
4. **Query** — any platform, agent, or human can check a counterparty's score
   before delegating or transacting.

## Repository structure

```
├── docs/spec.md                  # Protocol specification (v0.4)
├── schema/                       # JSON Schemas for identity & attestations
├── tools/simulate.py             # Scoring calibration harness (runs in CI)
├── src/agentcred/
│   ├── models.py                 # Core data objects
│   ├── canonical.py              # Canonical JSON form (signing/hashing input)
│   ├── crypto.py                 # Ed25519 keys, signing, verification, DIDs
│   ├── log.py                    # Hash-chained append-only record log
│   ├── scoring.py                # Calibrated, fault-aware scoring engine
│   ├── registry.py               # File-backed reference registry + disputes
│   ├── evidence.py               # Offline evidence-bundle verifier
│   ├── api.py                    # HTTP registry API (FastAPI)
│   └── cli.py                    # The `agentcred` command
└── tests/                        # Test suite (72 tests)
```

## Quickstart

```bash
pip install -e ".[crypto]"

# the agent you want scored
agentcred keygen --out seller.json
agentcred register --key seller.json --name invoice-bot --caps invoices.parse
#   → prints the identity incl. did:agentcred:xxx

# a counterparty vouches for real interactions (signed, chain-committed)
agentcred keygen --out buyer.json
agentcred register --key buyer.json --name payer-bot
agentcred attest --key buyer.json --agent did:agentcred:xxx \
    --type payment_settled --payload '{"value_usd": 120.00}'

agentcred query --agent did:agentcred:xxx   # score + band A–E
agentcred verify                            # chain + every signature
agentcred log                               # append-only history

# self-service, one-way: history is kept, new attestations stop
agentcred revoke --key seller.json

# compromise recovery without losing the identity: DID stays, key changes
agentcred keygen --out seller-v2.json
agentcred rotate --key seller.json --new-key seller-v2.json
```

## Disputes & evidence (v0.4)

When an attested interaction goes wrong, the court system takes over:

```bash
agentcred dispute-open --key buyer.json --target att_xxx --reason "task never completed"
# mutual settlement — both parties sign
agentcred dispute-resolve --dispute dsp_xxx --outcome rejected \
    --key buyer.json --key seller.json

# export the portable court document; anyone can verify it offline
agentcred evidence --dispute dsp_xxx --out bundle.json
agentcred verify-bundle --file bundle.json
```

Fault is assigned: **upheld** disputes damage the accused, **rejected**
and **settled** ones are lifted — a false accusation costs the accused
nothing. The evidence bundle carries the signed records and public keys,
so any arbiter, platform, or regulator can verify it without registry
access. Details in [spec §10](docs/spec.md).

## HTTP API (v0.3)

```bash
pip install -e ".[api]"
agentcred serve --state ./agentcred-state --port 8000
```

Private keys never leave clients — sign locally (spec §7), then submit:

```bash
# register (public JWK only)
curl -X POST localhost:8000/agents -H 'content-type: application/json' \
  -d '{"public_jwk": {"kty":"OKP","crv":"Ed25519","x":"..."},"display_name":"invoice-bot"}'

# trust report
curl localhost:8000/agents/did:agentcred:xxx

# integrity audit
curl localhost:8000/verify
```

`POST /attestations` verifies signatures server-side before committing to
the log; `POST /agents/{did}/revoke` proves authority with a signature over
the revocation intent. Full contract in [spec §9](docs/spec.md).

## Deploy

The registry is **stateful** — it needs a persistent disk, so run it where
volumes exist (not serverless):

```bash
# Docker anywhere
docker build -t agentcred .
docker run -p 8000:8000 -v agentcred-state:/data agentcred

# Render (blueprint with persistent disk + /health checks)
render blueprint launch

# Fly.io (volume + health checks preconfigured)
fly launch && fly deploy
```

State directory resolution: explicit argument → `AGENTCRED_STATE` env →
`./agentcred-state`.

## Status & roadmap

v0.4.1 shipped: Ed25519-signed attestations, tamper-evident chained logs,
the **court system** (structured disputes, fault assignment, evidence
bundles), an HTTP registry API, self-service revocation — and scoring
with a **180-day evidence half-life** (dormant agents slide, active ones
hold) plus a **serial-false-accuser penalty**. 12 trust invariants
enforced in CI. Next: dispute rate limiting, escrow on settlement rails
— see [ROADMAP.md](ROADMAP.md) and the [protocol spec](docs/spec.md).

## Contributing

Issues and PRs welcome — read the spec first, then open an issue describing
what you'd like to tackle.

## License

[MIT](LICENSE)
