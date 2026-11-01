"""Tests for structured disputes and evidence bundles (v0.4).

Runs under pytest, or standalone: python tests/test_disputes.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agentcred.crypto import generate_keypair, write_key  # noqa: E402
from agentcred.evidence import verify_bundle  # noqa: E402
from agentcred.registry import Registry  # noqa: E402


def setup_world(tmp: str, tasks: int = 10):
    seller_key = Path(tmp) / "seller.json"
    buyer_key = Path(tmp) / "buyer.json"
    arbiter_key = Path(tmp) / "arbiter.json"
    write_key(generate_keypair(), seller_key)
    write_key(generate_keypair(), buyer_key)
    write_key(generate_keypair(), arbiter_key)

    registry = Registry(Path(tmp) / "state")
    seller = registry.register(seller_key, display_name="seller")
    buyer = registry.register(buyer_key, display_name="buyer")
    arbiter = registry.register(arbiter_key, display_name="arbiter")

    att_ids = []
    for _ in range(tasks):
        att = registry.attest(
            seller["did"], "task_completed", key_file=buyer_key, payload={"task": "work"}
        )
        att_ids.append(att.id)
    return registry, seller_key, buyer_key, arbiter_key, seller["did"], buyer["did"], arbiter["did"], att_ids


def test_open_and_view():
    with tempfile.TemporaryDirectory() as tmp:
        (registry, _, buyer_key, _, seller_did, buyer_did, _, ids) = setup_world(tmp, tasks=1)
        opened = registry.open_dispute(ids[0], "work was wrong", key_file=buyer_key)
        assert opened["agent"] == seller_did
        view = registry.dispute_view(opened["id"])
        assert view["status"] == "open" and view["outcome"] is None
        assert registry.verify()["ok"]


def test_mutual_resolution_and_scoring():
    with tempfile.TemporaryDirectory() as tmp:
        (registry, seller_key, buyer_key, _, seller_did, _, _, ids) = setup_world(tmp)
        clean = registry.query(seller_did)["score"]

        upheld_id = registry.open_dispute(ids[0], "bad", key_file=buyer_key)["id"]
        registry.resolve_dispute(upheld_id, "upheld", key_files=[buyer_key, seller_key])
        hurt = registry.query(seller_did)
        assert hurt["metrics"]["disputes_upheld"] == 1
        assert hurt["score"] < clean

        rejected_id = registry.open_dispute(ids[1], "false alarm", key_file=buyer_key)["id"]
        registry.resolve_dispute(rejected_id, "rejected", key_files=[buyer_key, seller_key])
        lifted = registry.query(seller_did)
        assert lifted["metrics"]["disputes_lifted"] == 1
        assert lifted["score"] == hurt["score"]  # the false accusation cost nothing extra


def test_open_dispute_counts_provisionally():
    with tempfile.TemporaryDirectory() as tmp:
        (registry, _, buyer_key, _, seller_did, _, _, ids) = setup_world(tmp)
        clean = registry.query(seller_did)["score"]
        registry.open_dispute(ids[0], "pending", key_file=buyer_key)
        open_view = registry.query(seller_did)
        assert open_view["metrics"]["disputes_structured_open"] == 1
        assert open_view["score"] < clean


def test_mutual_resolution_requires_both():
    with tempfile.TemporaryDirectory() as tmp:
        (registry, _, buyer_key, _, _, _, _, ids) = setup_world(tmp, tasks=1)
        dsp = registry.open_dispute(ids[0], "bad", key_file=buyer_key)["id"]
        try:
            registry.resolve_dispute(dsp, "upheld", key_files=[buyer_key])
            raise AssertionError("one-sided mutual resolution accepted")
        except ValueError:
            pass


def test_arbiter_mode():
    with tempfile.TemporaryDirectory() as tmp:
        (registry, seller_key, buyer_key, arbiter_key, _, buyer_did, arbiter_did, ids) = setup_world(tmp, tasks=1)
        dsp = registry.open_dispute(
            ids[0], "needs a third party", key_file=buyer_key, arbiter=arbiter_did
        )["id"]
        # non-arbiter cannot resolve alone in arbiter mode
        try:
            registry.resolve_dispute(dsp, "rejected", key_files=[buyer_key, seller_key])
            raise AssertionError("non-arbiter resolved an arbiter dispute")
        except ValueError:
            pass
        entry = registry.resolve_dispute(dsp, "settled", key_files=[arbiter_key])
        assert arbiter_did in entry["resolved_by"]


def test_double_resolution_and_unknown_target_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        (registry, seller_key, buyer_key, _, _, _, _, ids) = setup_world(tmp, tasks=1)
        dsp = registry.open_dispute(ids[0], "x", key_file=buyer_key)["id"]
        registry.resolve_dispute(dsp, "settled", key_files=[buyer_key, seller_key])
        try:
            registry.resolve_dispute(dsp, "upheld", key_files=[buyer_key, seller_key])
            raise AssertionError("double resolution accepted")
        except ValueError:
            pass
        try:
            registry.open_dispute("att_missing", "x", key_file=buyer_key)
            raise AssertionError("dispute over unknown attestation accepted")
        except ValueError:
            pass


def test_evidence_bundle_verifies_and_detects_tampering():
    with tempfile.TemporaryDirectory() as tmp:
        (registry, seller_key, buyer_key, _, _, _, _, ids) = setup_world(tmp, tasks=1)
        dsp = registry.open_dispute(ids[0], "bad", key_file=buyer_key)["id"]
        registry.resolve_dispute(dsp, "upheld", key_files=[buyer_key, seller_key])

        bundle = registry.evidence_bundle(dsp)
        report = verify_bundle(bundle)
        assert report["ok"], report["problems"]
        assert report["signatures_valid"] == 4  # opening + 2 resolvers + target attestation

        forged = json.loads(json.dumps(bundle))
        forged["records"][0]["entry"]["reason"] = "fabricated"
        tampered = verify_bundle(forged)
        assert not tampered["ok"]
        assert any(p["issue"] == "record_hash_mismatch" for p in tampered["problems"])

        stolen = json.loads(json.dumps(bundle))
        stolen["identities"] = {}  # strip identities: signatures unverifiable
        no_ids = verify_bundle(stolen)
        assert not no_ids["ok"]


def test_registry_verify_covers_dispute_records():
    with tempfile.TemporaryDirectory() as tmp:
        (registry, seller_key, buyer_key, _, _, _, _, ids) = setup_world(tmp, tasks=1)
        dsp = registry.open_dispute(ids[0], "bad", key_file=buyer_key)["id"]
        registry.resolve_dispute(dsp, "upheld", key_files=[buyer_key, seller_key])
        report = registry.verify()
        assert report["ok"]
        assert report["signatures_valid"] == 4  # attestation + opening + 2 resolvers


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
