"""Deterministic scoring engine (v0.2.1, calibrated).

Implements the formula in docs/spec.md §4. Pure functions, no I/O, no
dependencies: anyone holding the same attestation log computes the same
score. Calibration invariants are enforced by tools/simulate.py in CI.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from .models import Attestation

SCORE_FLOOR = 300
BANDS = (
    ("A", 800),
    ("B", 700),
    ("C", 600),
    ("D", 500),
)


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def compute_metrics(
    attestations: Iterable[Attestation], now: str | None = None
) -> dict:
    """Aggregate counterparty attestations into raw metrics.

    Self-attestations are counted separately and excluded from score inputs.
    """
    now_dt = _parse(now) if now else datetime.now(timezone.utc)

    completed = disputes_open = settled = 0
    volume_usd = 0.0
    self_attestations = 0
    attesters: set[str] = set()
    first_seen: datetime | None = None

    for att in attestations:
        if att.is_self_attestation:
            self_attestations += 1
            continue
        if att.type == "task_completed":
            completed += 1
        elif att.type == "payment_settled":
            settled += 1
            volume_usd += float(att.payload.get("value_usd", 0.0) or 0.0)
        elif att.type == "dispute_opened":
            disputes_open += 1
        attesters.add(att.attester)
        signed = _parse(att.signed_at)
        if first_seen is None or signed < first_seen:
            first_seen = signed

    tenure_days = 0.0
    if first_seen is not None and first_seen <= now_dt:
        tenure_days = (now_dt - first_seen).total_seconds() / 86400.0

    return {
        "completed": completed,
        "disputes_open": disputes_open,
        "settled": settled,
        "volume_usd": round(volume_usd, 2),
        "tenure_days": round(tenure_days, 1),
        "self_attestations": self_attestations,
        "interactions": completed + settled,
        "distinct_attesters": len(attesters),
    }


def band_for(score: float) -> str:
    for label, threshold in BANDS:
        if score >= threshold:
            return label
    return "E"


def score_agent(attestations: Iterable[Attestation], now: str | None = None) -> dict:
    """Score an agent from its attestation log. See docs/spec.md §4.

    v0.2.1 calibration: reliability pays out only in proportion to depth
    (volume x attester diversity), so thin or single-source histories stay
    provisional no matter how clean they look.
    """
    m = compute_metrics(attestations, now=now)

    if m["interactions"] == 0 and m["disputes_open"] == 0:
        return {"score": SCORE_FLOOR, "band": band_for(SCORE_FLOOR), "metrics": m, "flags": ["unproven"]}

    interactions = m["interactions"]
    reliability = interactions / max(1, interactions + 2 * m["disputes_open"])
    depth = min(1.0, interactions / 20) * min(1.0, m["distinct_attesters"] / 3)
    value = min(1.0, m["volume_usd"] / 20000)
    tenure = min(1.0, m["tenure_days"] / 180)
    dispute_load = m["disputes_open"] / max(1, interactions)

    score = (
        SCORE_FLOOR
        + 350.0 * reliability * depth
        + 200.0 * depth
        + 100.0 * value
        + 50.0 * tenure
        - 300.0 * dispute_load
    )
    score = round(max(SCORE_FLOOR, min(900.0, score)), 1)

    flags: list[str] = []
    if m["disputes_open"] > 0 and reliability < 0.5:
        flags.append("elevated_dispute_signal")

    return {"score": score, "band": band_for(score), "metrics": m, "flags": flags}
