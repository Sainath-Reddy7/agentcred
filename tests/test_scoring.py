"""Tests for the v0 scoring engine.

Runs under pytest, or standalone: python tests/test_scoring.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agentcred.models import Attestation  # noqa: E402
from agentcred.scoring import band_for, compute_metrics, score_agent  # noqa: E402

NOW = "2026-11-01T00:00:00Z"
AGENT = "did:agentcred:agent1"
OTHER = "did:agentcred:counterparty1"


def att(aid: str, type_: str, value_usd: float = 0.0) -> Attestation:
    return Attestation(
        id=aid,
        agent=AGENT,
        attester=OTHER,
        type=type_,
        signed_at="2026-06-01T00:00:00Z",
        payload={"value_usd": value_usd} if value_usd else {},
    )


def test_unproven_agent_is_band_e():
    result = score_agent([], now=NOW)
    assert result["band"] == "E"
    assert result["score"] == 300
    assert "unproven" in result["flags"]


def test_self_attestations_do_not_count():
    log = [
        Attestation(id="a1", agent=AGENT, attester=AGENT, type="task_completed", signed_at="2026-06-01T00:00:00Z"),
        Attestation(id="a2", agent=AGENT, attester=AGENT, type="payment_settled", signed_at="2026-06-01T00:00:00Z", payload={"value_usd": 500}),
    ]
    result = score_agent(log, now=NOW)
    assert result["metrics"]["self_attestations"] == 2
    assert result["band"] == "E"


def test_clean_history_reaches_b_or_better():
    log = [att(f"a{i}", "task_completed") for i in range(40)]
    log += [att(f"p{i}", "payment_settled", value_usd=800.0) for i in range(30)]
    result = score_agent(log, now=NOW)
    assert result["band"] in ("A", "B"), result
    assert result["metrics"]["volume_usd"] == 24000.0


def test_disputes_crush_completion_rate():
    good = [att(f"a{i}", "task_completed") for i in range(10)]
    bad = [att(f"d{i}", "dispute_opened") for i in range(15)]
    clean = score_agent(good, now=NOW)
    disputed = score_agent(good + bad, now=NOW)
    assert disputed["score"] < clean["score"]
    assert "elevated_dispute_signal" in disputed["flags"]


def test_band_boundaries():
    assert band_for(900) == "A"
    assert band_for(800) == "A"
    assert band_for(799.9) == "B"
    assert band_for(600) == "C"
    assert band_for(499) == "E"


def test_metrics_volume_capping_indirectly():
    m = compute_metrics(
        [att("p1", "payment_settled", value_usd=200000.0)], now=NOW
    )
    assert m["volume_usd"] == 200000.0  # metric is raw; the cap lives in the score


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
    sys.exit(1 if failures else 0)
