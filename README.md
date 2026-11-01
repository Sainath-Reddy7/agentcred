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
├── docs/spec.md                  # Protocol specification (v0.2)
├── schema/                       # JSON Schemas for identity & attestations
├── src/agentcred/
│   ├── models.py                 # Core data objects
│   ├── canonical.py              # Canonical JSON form (signing/hashing input)
│   ├── crypto.py                 # Ed25519 keys, signing, verification, DIDs
│   ├── log.py                    # Hash-chained append-only attestation log
│   ├── scoring.py                # Deterministic scoring engine
│   ├── registry.py               # File-backed reference registry
│   └── cli.py                    # The `agentcred` command
└── tests/                        # Test suite (27 tests)
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
```

## Status & roadmap

v0.2 shipped: real Ed25519-signed attestations, a tamper-evident hash-chained
log, and the CLI above. Next: registry REST API and owner-key rotation — see
[ROADMAP.md](ROADMAP.md) and the [protocol spec](docs/spec.md).

## Contributing

Issues and PRs welcome — read the spec first, then open an issue describing
what you'd like to tackle.

## License

[MIT](LICENSE)
