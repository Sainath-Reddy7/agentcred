"""Population simulation harness — validates scoring invariants (spec §4).

Builds synthetic agent histories (honest, thin, dispute-prone, sybil,
payment-only) and asserts the score each one deserves. An honest trust
system must fail loudly when it rewards the wrong agents.

Run: python tools/simulate.py   (exit 1 on any invariant failure; used in CI)
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agentcred.models import Attestation  # noqa: E402
from agentcred.scoring import score_agent  # noqa: E402

NOW = "2026-11-01T00:00:00Z"
AGENT = "did:agentcred:sim1"
BASE = datetime(2026, 11, 1, tzinfo=timezone.utc)


def ts(days_ago: int) -> str:
    return (BASE - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def many(
    prefix: str,
    type_: str,
    count: int,
    attesters: int,
    days_span: int,
    value_usd: float = 0.0,
) -> list[Attestation]:
    out = []
    for i in range(count):
        attester = f"did:agentcred:cp{i % attesters + 1:02d}"
        day = max(2, days_span - (days_span * i) // max(1, count))
        payload = {"value_usd": value_usd} if value_usd else {}
        out.append(
            Attestation(
                id=f"{prefix}{i}",
                agent=AGENT,
                attester=attester,
                type=type_,
                signed_at=ts(day),
                payload=payload,
            )
        )
    return out


SCENARIOS = [
    (
        "fresh_honest",
        lambda: many("f", "task_completed", 1, 1, 3)
        + many("p", "payment_settled", 1, 1, 3, value_usd=120),
        lambda r: r["band"] == "E",
        "2 interactions, 1 attester: thin history must stay provisional (E)",
    ),
    (
        "one_hit_wonder",
        lambda: many("w", "task_completed", 1, 1, 0),
        lambda r: r["band"] == "E",
        "a single task cannot reach A/B — the v0.2 wound",
    ),
    (
        "established_honest",
        lambda: many("e", "task_completed", 40, 6, 200)
        + many("v", "payment_settled", 25, 6, 200, value_usd=1200),
        lambda r: r["band"] == "A",
        "65 interactions, 6 attesters, $30k, 200 days: must reach A",
    ),
    (
        "growing_honest",
        lambda: many("g", "task_completed", 12, 3, 60),
        lambda r: "C" == r["band"] or "D" == r["band"],
        "12 interactions, 3 attesters: mid-band, neither top nor floor",
    ),
    (
        "dispute_prone",
        lambda: many("d1", "task_completed", 10, 4, 150)
        + many("d2", "payment_settled", 10, 4, 150, value_usd=100)
        + many("d3", "dispute_opened", 10, 4, 150),
        lambda r: r["score"] < 600,
        "1 in 2 interactions disputed: D or worse",
    ),
    (
        "sybil_pair",
        lambda: many("s", "task_completed", 25, 1, 30),
        lambda r: r["score"] < 500,
        "25 attestations from ONE counterparty: contained at E until diversity grows",
    ),
    (
        "payment_only_clean",
        lambda: many("po", "payment_settled", 25, 4, 150, value_usd=600),
        lambda r: r["score"] >= 700,
        "25 clean settlements from 4 attesters: payments count as reliability",
    ),
]


def main() -> int:
    width = max(len(name) for name, _, _, _ in SCENARIOS)
    failures = 0
    print(f"{'scenario':<{width}}  band  score   int  atts  verdict")
    print("-" * (width + 44))
    for name, build, check, why in SCENARIOS:
        result = score_agent(build(), now=NOW)
        m = result["metrics"]
        ok = check(result)
        if not ok:
            failures += 1
        verdict = "PASS" if ok else f"FAIL — {why}"
        print(
            f"{name:<{width}}  {result['band']:>4}  {result['score']:>6.1f}"
            f"  {m['completed'] + m['settled']:>4}  {m.get('distinct_attesters', 0):>4}  {verdict}"
        )
    known_limits = (
        "\nknown limits (documented, not solved): collusion rings of >=3 attesters"
        "\nstill score; no time decay for stale histories yet (roadmap v0.4)."
    )
    print(known_limits if failures == 0 else "")
    print(f"\n{len(SCENARIOS) - failures}/{len(SCENARIOS)} invariants hold")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
