"""Tests for deals and attestation-gated settlement (v0.6).

Runs under pytest, or standalone: python tests/test_deals.py
"""

from __future__ import annotations

import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agentcred.crypto import generate_keypair, write_key  # noqa: E402
from agentcred.registry import Registry  # noqa: E402

FUTURE = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
PAST = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")


def setup_world(tmp: str):
    payer_key = Path(tmp) / "payer.json"
    payee_key = Path(tmp) / "payee.json"
    arbiter_key = Path(tmp) / "arbiter.json"
    for path in (payer_key, payee_key, arbiter_key):
        write_key(generate_keypair(), path)
    registry = Registry(Path(tmp) / "state")
    payer = registry.register(payer_key, display_name="payer")
    payee = registry.register(payee_key, display_name="payee")
    arbiter = registry.register(arbiter_key, display_name="arbiter")
    return registry, payer_key, payee_key, arbiter_key, payer["did"], payee["did"], arbiter["did"]


def open_default(registry, payer_key, payee_key, payee_did, **kwargs):
    return registry.open_deal(
        payee=payee_did, amount_usd=100.0, condition_type="task_completed",
        payer_key_file=payer_key, payee_key_file=payee_key,
        terms="build the thing", **kwargs,
    )


def test_happy_path_attestation_gated_settlement():
    with tempfile.TemporaryDirectory() as tmp:
        (registry, payer_key, payee_key, _, payer_did, payee_did, _) = setup_world(tmp)
        deal = open_default(registry, payer_key, payee_key, payee_did, deadline=FUTURE)

        # the condition: payer attests the payee completed the work, bound to the deal
        att = registry.attest(
            payee_did, "task_completed", key_file=payer_key,
            payload={"deal": deal["id"], "value_usd": 100.0},
        )
        registry.settle_deal(deal["id"], settlement=att.id, key_file=payer_key)

        view = registry.deal_view(deal["id"])
        assert view["status"] == "settled"
        assert view["settlement"] == att.id

        report = registry.verify()
        assert report["ok"], report["problems"]
        # deal.opened (2) + condition attestation (1) + settlement (1)
        assert report["signatures_valid"] == 4


def test_settlement_requires_deal_bound_attestation():
    with tempfile.TemporaryDirectory() as tmp:
        (registry, payer_key, payee_key, _, _, payee_did, _) = setup_world(tmp)
        deal = open_default(registry, payer_key, payee_key, payee_did)

        free_att = registry.attest(payee_did, "task_completed", key_file=payer_key)
        try:
            registry.settle_deal(deal["id"], settlement=free_att.id, key_file=payer_key)
            raise AssertionError("settled with an attestation not bound to the deal")
        except ValueError:
            pass
        assert registry.deal_view(deal["id"])["status"] == "open"


def test_settlement_rejects_wrong_shape():
    with tempfile.TemporaryDirectory() as tmp:
        (registry, payer_key, payee_key, arbiter_key, payer_did, payee_did, _) = setup_world(tmp)
        deal = open_default(registry, payer_key, payee_key, payee_did, deadline=FUTURE)

        # wrong condition type, deal-bound
        wrong_type = registry.attest(
            payee_did, "capability_verified", key_file=payer_key, payload={"deal": deal["id"]}
        )
        # right type, wrong attestor (payee attesting about itself)
        wrong_signer = registry.attest(
            payee_did, "task_completed", key_file=payee_key, payload={"deal": deal["id"]}
        )
        for bad in (wrong_type.id, wrong_signer.id):
            try:
                registry.settle_deal(deal["id"], settlement=bad, key_file=payer_key)
                raise AssertionError(f"settled against {bad}")
            except ValueError:
                pass
        # payee cannot settle at all
        good = registry.attest(
            payee_did, "task_completed", key_file=payer_key, payload={"deal": deal["id"]}
        )
        try:
            registry.settle_deal(deal["id"], settlement=good.id, key_file=payee_key)
            raise AssertionError("payee settled its own deal")
        except ValueError:
            pass


def test_deadline_and_arbiter_grace():
    import time

    with tempfile.TemporaryDirectory() as tmp:
        (registry, payer_key, payee_key, arbiter_key, payer_did, payee_did, arbiter_did) = setup_world(tmp)
        # validly opened with a near-future deadline; let it elapse
        near = (datetime.now(timezone.utc) + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        deal = registry.open_deal(
            payee=payee_did, amount_usd=50.0, condition_type="task_completed",
            payer_key_file=payer_key, payee_key_file=payee_key,
            deadline=near, arbiter=arbiter_did,
        )
        time.sleep(2)
        att = registry.attest(
            payee_did, "task_completed", key_file=arbiter_key, payload={"deal": deal["id"]}
        )
        try:
            registry.settle_deal(deal["id"], settlement=att.id, key_file=payer_key)
            raise AssertionError("payer settled past the deadline")
        except ValueError:
            pass
        registry.settle_deal(deal["id"], settlement=att.id, key_file=arbiter_key)  # arbiter grace
        assert registry.deal_view(deal["id"])["status"] == "settled"


def test_cancel_and_terminal_states():
    with tempfile.TemporaryDirectory() as tmp:
        (registry, payer_key, payee_key, _, _, payee_did, _) = setup_world(tmp)
        deal = open_default(registry, payer_key, payee_key, payee_did)
        registry.cancel_deal(deal["id"], payer_key_file=payer_key, payee_key_file=payee_key)
        assert registry.deal_view(deal["id"])["status"] == "cancelled"

        att = registry.attest(
            payee_did, "task_completed", key_file=payer_key, payload={"deal": deal["id"]}
        )
        try:
            registry.settle_deal(deal["id"], settlement=att.id, key_file=payer_key)
            raise AssertionError("settled a cancelled deal")
        except ValueError:
            pass


def test_expired_status_derived():
    import time

    with tempfile.TemporaryDirectory() as tmp:
        (registry, payer_key, payee_key, _, _, payee_did, _) = setup_world(tmp)
        near = (datetime.now(timezone.utc) + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        deal = open_default(registry, payer_key, payee_key, payee_did, deadline=near)
        assert registry.deal_view(deal["id"])["status"] == "open"
        time.sleep(2)
        assert registry.deal_view(deal["id"])["status"] == "expired"


def test_open_validations():
    with tempfile.TemporaryDirectory() as tmp:
        (registry, payer_key, payee_key, _, payer_did, payee_did, _) = setup_world(tmp)
        # payer and payee must differ
        try:
            open_default(registry, payer_key, payee_key, payer_did)
            raise AssertionError("self-deal accepted")
        except ValueError:
            pass
        # deadline must be after opening
        try:
            open_default(registry, payer_key, payee_key, payee_did, deadline=PAST)
            raise AssertionError("past deadline accepted")
        except ValueError:
            pass


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
