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
EVIDENCE_HALF_LIFE_DAYS = 180.0
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
    effective_interactions = 0.0
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
        if att.type in ("task_completed", "payment_settled"):
            age_days = max(0.0, (now_dt - signed).total_seconds() / 86400.0)
            effective_interactions += min(
                1.0, 0.5 ** (age_days / EVIDENCE_HALF_LIFE_DAYS)
            )

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
        "effective_interactions": round(effective_interactions, 2),
        "distinct_attesters": len(attesters),
    }


def band_for(score: float) -> str:
    for label, threshold in BANDS:
        if score >= threshold:
            return label
    return "E"


def _dispute_effect(disputes: Iterable[dict] | None) -> dict:
    """Fold structured dispute views into counting buckets.

    Fault assignment (v0.4): upheld disputes count against the agent;
    rejected and settled (mutual, no fault) are lifted — they do not count.
    Open disputes count provisionally, like raw v0.2 dispute attestations.
    """
    open_now = upheld = lifted = 0
    for d in disputes or []:
        if d.get("status") == "resolved":
            if d.get("outcome") == "upheld":
                upheld += 1
            else:  # rejected or settled
                lifted += 1
        else:
            open_now += 1
    return {"open": open_now, "upheld": upheld, "lifted": lifted}


def score_agent(
    attestations: Iterable[Attestation],
    now: str | None = None,
    disputes: Iterable[dict] | None = None,
    false_accusations: int = 0,
) -> dict:
    """Score an agent from its attestation log and structured disputes.

    See docs/spec.md §4. v0.2.1 calibration: reliability pays out only in
    proportion to depth (volume x attester diversity). v0.4: dispute fault
    is assigned — upheld disputes count against the agent, rejected/settled
    ones are lifted.
    """
    m = compute_metrics(attestations, now=now)
    dv = _dispute_effect(disputes)
    m["disputes_structured_open"] = dv["open"]
    m["disputes_upheld"] = dv["upheld"]
    m["disputes_lifted"] = dv["lifted"]
    m["false_accusations"] = false_accusations
    total_disputes = m["disputes_open"] + dv["open"] + dv["upheld"]

    if m["interactions"] == 0 and total_disputes == 0 and false_accusations == 0:
        return {
            "score": SCORE_FLOOR,
            "band": band_for(SCORE_FLOOR),
            "metrics": m,
            "flags": ["unproven"],
            "factors": {"base": SCORE_FLOOR},
        }

    interactions = m["interactions"]
    reliability = interactions / max(1, interactions + 2 * total_disputes)
    depth = min(1.0, m["effective_interactions"] / 20) * min(1.0, m["distinct_attesters"] / 3)
    value = min(1.0, m["volume_usd"] / 20000)
    tenure = min(1.0, m["tenure_days"] / 180)
    dispute_load = min(1.0, total_disputes / max(1, interactions))
    accuser_load = min(1.0, false_accusations / 3)

    factors = {
        "base": SCORE_FLOOR,
        "reliability_x_depth": round(350.0 * reliability * depth, 1),
        "track_record_depth": round(200.0 * depth, 1),
        "settled_value": round(100.0 * value, 1),
        "tenure": round(50.0 * tenure, 1),
        "dispute_load": round(-300.0 * dispute_load, 1) + 0.0,  # +0.0 avoids -0.0
        "false_accusations": round(-100.0 * accuser_load, 1) + 0.0,
    }
    score = SCORE_FLOOR + sum(v for k, v in factors.items() if k != "base")
    score = round(max(SCORE_FLOOR, min(900.0, score)), 1)

    flags: list[str] = []
    if total_disputes > 0 and reliability < 0.5:
        flags.append("elevated_dispute_signal")
    if false_accusations >= 2:
        flags.append("serial_false_accuser")

    return {"score": score, "band": band_for(score), "metrics": m, "flags": flags, "factors": factors}
