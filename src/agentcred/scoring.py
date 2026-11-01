"""Deterministic v0 scoring engine.

Implements the formula in docs/spec.md §4. Pure functions, no I/O, no
dependencies: anyone holding the same attestation log computes the same
score. Signature verification is out of scope until v0.2.
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
    }


def band_for(score: float) -> str:
    for label, threshold in BANDS:
        if score >= threshold:
            return label
    return "E"


def score_agent(attestations: Iterable[Attestation], now: str | None = None) -> dict:
    """Score an agent from its attestation log. See docs/spec.md §4."""
    m = compute_metrics(attestations, now=now)

    if m["completed"] == 0 and m["settled"] == 0 and m["disputes_open"] == 0:
        return {"score": SCORE_FLOOR, "band": band_for(SCORE_FLOOR), "metrics": m, "flags": ["unproven"]}

    completion_rate = m["completed"] / max(1, m["completed"] + m["disputes_open"])
    score = (
        SCORE_FLOOR
        + 550.0 * completion_rate
        + min(50.0, float(m["settled"]))
        + min(50.0, m["volume_usd"] / 1000.0)
        + min(50.0, m["tenure_days"] / 180.0)
    )
    score = round(min(score, 900.0), 1)

    flags: list[str] = []
    if m["disputes_open"] > 0 and completion_rate < 0.5:
        flags.append("elevated_dispute_signal")

    return {"score": score, "band": band_for(score), "metrics": m, "flags": flags}
