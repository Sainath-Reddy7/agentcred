"""Tests for the calibrated scoring engine (v0.2.1).

Runs under pytest, or standalone: python tests/test_scoring.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agentcred.models import Attestation  # noqa: E402
from agentcred.scoring import band_for, compute_metrics, score_agent  # noqa: E402

BASE = datetime(2026, 11, 1, tzinfo=timezone.utc)
NOW = BASE.strftime("%Y-%m-%dT%H:%M:%SZ")
AGENT = "did:agentcred:agent1"


def att(
    aid: str,
    type_: str,
    value_usd: float = 0.0,
    attester: int | str = 1,
    days_ago: int = 150,
) -> Attestation:
    if isinstance(attester, int):
        attester = f"did:agentcred:cp{attester:02d}"
    signed = (BASE - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = {"value_usd": value_usd} if value_usd else {}
    return Attestation(
        id=aid, agent=AGENT, attester=attester, type=type_, signed_at=signed, payload=payload
    )


def diverse_clean_history() -> list[Attestation]:
    out = []
    for i in range(40):
        out.append(att(f"t{i}", "task_completed", attester=i % 6 + 1, days_ago=5 + 195 * i // 40))
    for i in range(25):
        out.append(att(f"p{i}", "payment_settled", value_usd=1200.0, attester=i % 6 + 1, days_ago=5 + 195 * i // 25))
    return out


def test_unproven_agent_is_band_e():
    result = score_agent([], now=NOW)
    assert result["band"] == "E"
    assert result["score"] == 300
    assert "unproven" in result["flags"]


def test_self_attestations_do_not_count():
    me = "did:agentcred:agent1"
    log = [
        Attestation(id="a1", agent=me, attester=me, type="task_completed", signed_at="2026-06-01T00:00:00Z"),
        Attestation(id="a2", agent=me, attester=me, type="payment_settled", signed_at="2026-06-01T00:00:00Z", payload={"value_usd": 500}),
    ]
    result = score_agent(log, now=NOW)
    assert result["metrics"]["self_attestations"] == 2
    assert result["band"] == "E"


def test_clean_diverse_history_reaches_a():
    result = score_agent(diverse_clean_history(), now=NOW)
    assert result["band"] == "A", result


def test_single_attester_history_caps_at_c():
    same = [
        att(f"t{i}", "task_completed", attester=1, days_ago=5 + 195 * i // 40)
        for i in range(40)
    ] + [
        att(f"p{i}", "payment_settled", value_usd=1200.0, attester=1, days_ago=5 + 195 * i // 25)
        for i in range(25)
    ]
    result = score_agent(same, now=NOW)
    assert 600 <= result["score"] < 700, result  # diversity gates depth


def test_one_interaction_stays_provisional():
    log = [att("t0", "task_completed"), att("p0", "payment_settled", value_usd=120.0)]
    result = score_agent(log, now=NOW)
    assert result["band"] == "E"
    assert result["score"] < 400


def test_payment_only_history_progresses():
    log = [
        att(f"p{i}", "payment_settled", value_usd=600.0, attester=i % 4 + 1, days_ago=150)
        for i in range(25)
    ]
    result = score_agent(log, now=NOW)
    assert result["score"] >= 700, result  # payments are reliability too


def test_sybil_pair_contained():
    log = [att(f"t{i}", "task_completed", attester=1, days_ago=30) for i in range(25)]
    result = score_agent(log, now=NOW)
    assert result["score"] < 500, result  # single counterparty caps depth


def test_disputes_crush_score():
    good = [att(f"a{i}", "task_completed") for i in range(10)]
    bad = [att(f"d{i}", "dispute_opened") for i in range(15)]
    clean = score_agent(good, now=NOW)
    disputed = score_agent(good + bad, now=NOW)
    assert disputed["score"] < clean["score"]
    assert "elevated_dispute_signal" in disputed["flags"]


def test_dispute_only_history_floors_at_300():
    log = [att(f"d{i}", "dispute_opened") for i in range(5)]
    result = score_agent(log, now=NOW)
    assert result["score"] == 300  # capped dispute load, not a lucky clamp
    assert result["band"] == "E"
    assert "elevated_dispute_signal" in result["flags"]


def test_band_boundaries():
    assert band_for(900) == "A"
    assert band_for(800) == "A"
    assert band_for(799.9) == "B"
    assert band_for(600) == "C"
    assert band_for(499) == "E"


def test_metrics_report_interactions_and_diversity():
    m = compute_metrics(
        [att("a", "task_completed", attester=1), att("b", "payment_settled", value_usd=5, attester=2)],
        now=NOW,
    )
    assert m["interactions"] == 2
    assert m["distinct_attesters"] == 2
    assert m["effective_interactions"] > 0


def test_decay_discounts_stale_evidence():
    fresh = [att(f"f{i}", "task_completed", attester=i % 4 + 1, days_ago=10) for i in range(25)]
    stale = [att(f"s{i}", "task_completed", attester=i % 4 + 1, days_ago=365) for i in range(25)]
    fresh_r = score_agent(fresh, now=NOW)
    stale_r = score_agent(stale, now=NOW)
    assert fresh_r["score"] - stale_r["score"] > 100
    assert stale_r["metrics"]["effective_interactions"] < stale_r["metrics"]["interactions"]


def test_false_accusations_penalized_and_flagged():
    base = [att(f"t{i}", "task_completed", attester=i % 3 + 1, days_ago=60) for i in range(12)]
    clean = score_agent(base, now=NOW)
    guilty = score_agent(base, now=NOW, false_accusations=3)
    assert guilty["score"] < clean["score"]
    assert "serial_false_accuser" in guilty["flags"]
    assert guilty["metrics"]["false_accusations"] == 3
    # one mistake is human: no flag below two
    one_off = score_agent(base, now=NOW, false_accusations=1)
    assert "serial_false_accuser" not in one_off["flags"]


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
