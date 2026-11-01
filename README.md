# AgentCred

<p align="center">
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
├── docs/spec.md                  # Protocol specification (v0-draft)
├── schema/                       # JSON Schemas for identity & attestations
├── src/agentcred/
│   ├── models.py                 # Core data objects
│   └── scoring.py                # Deterministic v0 scoring engine
└── tests/                        # Test suite
```

## Status & roadmap

Research & prototype — see [ROADMAP.md](ROADMAP.md) and the
[protocol spec](docs/spec.md). The v0 scoring engine implements the deterministic
baseline described in the spec; signature verification and the registry API are next.

## Contributing

Issues and PRs welcome — read the spec first, then open an issue describing
what you'd like to tackle.

## License

[MIT](LICENSE)
