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


def test_false_accuser_penalized_in_query():
    with tempfile.TemporaryDirectory() as tmp:
        (registry, seller_key, buyer_key, arbiter_key, seller_did, buyer_did, arbiter_did, ids) = setup_world(tmp, tasks=10)
        # give the buyer (accuser) a real history from two counterparties
        for _ in range(5):
            registry.attest(buyer_did, "task_completed", key_file=seller_key)
            registry.attest(buyer_did, "task_completed", key_file=arbiter_key)
        clean = registry.query(buyer_did)

        for target in ids[:2]:
            dsp = registry.open_dispute(target, "fabricated", key_file=buyer_key)["id"]
            registry.resolve_dispute(dsp, "rejected", key_files=[buyer_key, seller_key])

        guilty = registry.query(buyer_did)
        assert guilty["metrics"]["false_accusations"] == 2
        assert "serial_false_accuser" in guilty["flags"]
        assert guilty["score"] < clean["score"]
        # the accused is untouched by rejected accusations
        assert registry.query(seller_did)["metrics"]["disputes_lifted"] == 2


def test_duplicate_open_dispute_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        (registry, _, buyer_key, _, _, _, _, ids) = setup_world(tmp, tasks=2)
        registry.open_dispute(ids[0], "bad", key_file=buyer_key)
        try:
            registry.open_dispute(ids[0], "again", key_file=buyer_key)
            raise AssertionError("duplicate open dispute accepted")
        except ValueError:
            pass


def test_opener_cap_and_release_on_resolution():
    with tempfile.TemporaryDirectory() as tmp:
        (registry, seller_key, buyer_key, _, seller_did, _, _, ids) = setup_world(tmp, tasks=6)
        opened = [
            registry.open_dispute(target, "g", key_file=buyer_key)["id"]
            for target in ids[:5]
        ]
        try:
            registry.open_dispute(ids[5], "one too many", key_file=buyer_key)
            raise AssertionError("sixth open dispute accepted")
        except ValueError:
            pass
        # resolving frees capacity
        registry.resolve_dispute(opened[0], "settled", key_files=[buyer_key, seller_key])
        registry.open_dispute(ids[5], "ok now", key_file=buyer_key)


def test_pile_on_cap():
    with tempfile.TemporaryDirectory() as tmp:
        (registry, seller_key, buyer_key, _, seller_did, buyer_did, _, ids) = setup_world(tmp, tasks=1)
        witnesses = []
        for n in range(4):
            key = Path(tmp) / f"w{n}.json"
            write_key(generate_keypair(), key)
            witnesses.append(key)
            registry.register(key, display_name=f"witness{n}")
        # three distinct openers may pile on; the fourth is refused
        for key in [buyer_key] + witnesses[:2]:
            registry.open_dispute(ids[0], "pile on", key_file=key)
        try:
            registry.open_dispute(ids[0], "too many", key_file=witnesses[3])
            raise AssertionError("fourth open dispute on one target accepted")
        except ValueError:
            pass


def test_bundle_rejects_swapped_target_attestation():
    """A court document must be bound to the exact attestation it names."""
    with tempfile.TemporaryDirectory() as tmp:
        (registry, seller_key, buyer_key, _, seller_did, _, _, _) = setup_world(tmp, tasks=2)
        contested = registry.attestations_for(seller_did)[0]
        other = registry.attestations_for(seller_did)[1]
        dsp = registry.open_dispute(contested.id, "contested", key_file=buyer_key)["id"]
        registry.resolve_dispute(dsp, "rejected", key_files=[buyer_key, seller_key])

        bundle = json.loads(json.dumps(registry.evidence_bundle(dsp)))
        # swap in a DIFFERENT fully-valid attestation record (own hash, own signature)
        from agentcred.log import load

        other_rec = [r for r in load(registry.log_path) if r.entry.get("id") == other.id][0]
        for i, rec in enumerate(bundle["records"]):
            if rec["entry"].get("kind", "attestation") == "attestation":
                bundle["records"][i] = {
                    "index": other_rec.index, "prev": other_rec.prev,
                    "entry": other_rec.entry, "hash": other_rec.hash,
                }
        report = verify_bundle(bundle)
        assert not report["ok"]
        assert any(p["issue"] == "target_mismatch" for p in report["problems"])


def test_dispute_timestamps_validated():
    with tempfile.TemporaryDirectory() as tmp:
        (registry, seller_key, buyer_key, _, seller_did, buyer_did, _, ids) = setup_world(tmp, tasks=3)

        bad_open = {
            "kind": "dispute.opened", "id": "dsp_ts1", "target": ids[0], "agent": seller_did,
            "opened_by": buyer_did, "reason": "x", "opened_at": "not-a-date", "arbiter": None,
        }
        try:
            registry.commit_open_dispute(bad_open, ["sig"])
            raise AssertionError("garbage opened_at accepted")
        except ValueError:
            pass

        future_open = dict(bad_open, id="dsp_ts2", opened_at="2030-01-01T00:00:00Z")
        try:
            registry.commit_open_dispute(future_open, ["sig"])
            raise AssertionError("year-2030 opened_at accepted")
        except ValueError:
            pass

        opened = registry.open_dispute(ids[1], "ok", key_file=buyer_key)
        missing_res = {
            "kind": "dispute.resolved", "dispute": opened["id"], "outcome": "rejected",
            "resolved_by": [buyer_did, seller_did],
        }
        try:
            registry.commit_resolution(missing_res, ["sig", "sig"])
            raise AssertionError("resolution without resolved_at accepted")
        except ValueError:
            pass
        # the view must never crash on committed state
        assert registry.dispute_view(opened["id"])["status"] == "open"


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
