"""Tests for the file-backed registry (v0.2).

Runs under pytest, or standalone: python tests/test_registry.py
"""

from __future__ import annotations

import json
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agentcred.crypto import write_key, generate_keypair  # noqa: E402
from agentcred.log import append  # noqa: E402
from agentcred.registry import Registry  # noqa: E402


def setup_world(tmp: str) -> tuple[Path, Path, Path, str, str]:
    """Seller agent + buyer counterparty, both registered."""
    seller_key = Path(tmp) / "seller.json"
    buyer_key = Path(tmp) / "buyer.json"
    write_key(generate_keypair(), seller_key)
    write_key(generate_keypair(), buyer_key)

    registry = Registry(Path(tmp) / "state")
    seller = registry.register(seller_key, display_name="invoice-bot", capabilities=("invoices.parse",))
    buyer = registry.register(buyer_key, display_name="payer-bot")
    return registry, seller_key, buyer_key, seller["did"], buyer["did"]


def test_register_and_reregister_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        registry, seller_key, _, _, _ = setup_world(tmp)
        try:
            registry.register(seller_key, display_name="copycat")
        except ValueError:
            pass
        else:
            raise AssertionError("same key registered twice")


def test_attest_then_query_counts():
    with tempfile.TemporaryDirectory() as tmp:
        registry, _, buyer_key, seller_did, _ = setup_world(tmp)
        for _ in range(3):
            registry.attest(
                seller_did, "task_completed", key_file=buyer_key, payload={"task": "invoices"}
            )
        registry.attest(
            seller_did, "payment_settled", key_file=buyer_key, payload={"value_usd": 250.0}
        )
        result = registry.query(seller_did)
        assert result["metrics"]["completed"] == 3
        assert result["metrics"]["settled"] == 1
        assert result["metrics"]["volume_usd"] == 250.0
        assert result["identity"]["display_name"] == "invoice-bot"


def test_unregistered_attester_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        registry, _, _, seller_did, _ = setup_world(tmp)
        stranger = Path(tmp) / "stranger.json"
        write_key(generate_keypair(), stranger)
        try:
            registry.attest(seller_did, "task_completed", key_file=stranger)
        except ValueError:
            pass
        else:
            raise AssertionError("unregistered attester was accepted")


def test_verify_clean_then_tampered():
    with tempfile.TemporaryDirectory() as tmp:
        registry, _, buyer_key, seller_did, _ = setup_world(tmp)
        registry.attest(seller_did, "task_completed", key_file=buyer_key)

        clean = registry.verify()
        assert clean["ok"] and clean["signatures_valid"] == 1

        # forge a record's entry directly in the log file
        lines = registry.log_path.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[0])
        record["entry"]["type"] = "payment_settled"
        record["entry"]["payload"] = {"value_usd": 10**9}
        lines[0] = json.dumps(record, separators=(",", ":"), sort_keys=True)
        registry.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        report = registry.verify()
        assert not report["ok"]
        assert report["chain"] != "ok"


def test_unknown_attester_flagged():
    with tempfile.TemporaryDirectory() as tmp:
        registry, _, buyer_key, seller_did, _ = setup_world(tmp)
        registry.attest(seller_did, "task_completed", key_file=buyer_key)
        # smuggle in a record from a did that was never registered
        forged = {
            "id": "att_evil",
            "agent": seller_did,
            "attester": "did:agentcred:deadbeefcafe",
            "type": "task_completed",
            "payload": {},
            "signed_at": "2026-11-01T00:00:00Z",
        }
        append(registry.log_path, forged)
        report = registry.verify()
        assert not report["ok"]
        assert any(p["issue"] == "unknown_attester" for p in report["problems"])


def test_unknown_agent_flagged():
    with tempfile.TemporaryDirectory() as tmp:
        registry, _, buyer_key, seller_did, _ = setup_world(tmp)
        registry.attest(seller_did, "task_completed", key_file=buyer_key)
        ghost = dict(registry.attestations_for(seller_did)[0].to_dict())
        ghost["agent"] = "did:agentcred:ghost404"
        append(registry.log_path, ghost)
        report = registry.verify()
        assert any(p["issue"] == "unknown_agent" for p in report["problems"])


def test_attestation_ids_unique_same_second():
    with tempfile.TemporaryDirectory() as tmp:
        registry, _, buyer_key, seller_did, _ = setup_world(tmp)
        first = registry.attest(seller_did, "task_completed", key_file=buyer_key)
        second = registry.attest(seller_did, "task_completed", key_file=buyer_key)
        assert first.id != second.id


def test_attestation_replay_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        registry, _, buyer_key, seller_did, _ = setup_world(tmp)
        att = registry.attest(seller_did, "task_completed", key_file=buyer_key)
        try:
            registry.record(att)  # resubmit the identical signed attestation
            raise AssertionError("replayed attestation accepted")
        except ValueError:
            pass
        assert len(registry.attestations_for(seller_did)) == 1
        assert registry.query(seller_did)["metrics"]["interactions"] == 1


def test_revoked_agent_rejected_as_subject_and_attester():
    with tempfile.TemporaryDirectory() as tmp:
        registry, seller_key, buyer_key, seller_did, buyer_did = setup_world(tmp)
        registry.revoke(seller_did, key_file=seller_key)
        try:
            registry.attest(seller_did, "task_completed", key_file=buyer_key)
            raise AssertionError("attestation about a revoked agent was accepted")
        except ValueError:
            pass
        try:
            registry.attest(buyer_did, "task_completed", key_file=seller_key)
            raise AssertionError("revoked attester was accepted")
        except ValueError:
            pass


def test_revoke_requires_possession_of_key():
    with tempfile.TemporaryDirectory() as tmp:
        registry, seller_key, buyer_key, seller_did, _ = setup_world(tmp)
        try:
            registry.revoke(seller_did, key_file=buyer_key)
            raise AssertionError("revoked with someone else's key")
        except ValueError:
            pass


def test_revoke_is_one_way_and_flagged_in_query():
    with tempfile.TemporaryDirectory() as tmp:
        registry, seller_key, buyer_key, seller_did, _ = setup_world(tmp)
        registry.attest(seller_did, "task_completed", key_file=buyer_key)
        identity = registry.revoke(seller_did, key_file=seller_key)
        assert identity["revoked"] and identity["version"] == 2 and "revoked_at" in identity
        try:
            registry.revoke(seller_did, key_file=seller_key)
            raise AssertionError("double revocation accepted")
        except ValueError:
            pass
        result = registry.query(seller_did)
        assert "revoked" in result["flags"]
        assert result["metrics"]["completed"] == 1  # history preserved


def test_query_unknown_agent_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        registry, _, _, _, _ = setup_world(tmp)
        try:
            registry.query("did:agentcred:nobody")
        except ValueError:
            pass
        else:
            raise AssertionError("query on unknown agent succeeded")


def test_concurrent_registrations_do_not_lose_identities():
    """agents.json mutations must be serialized — uvicorn runs sync
    endpoints in a threadpool, and the unlocked version lost 8 of 10."""
    with tempfile.TemporaryDirectory() as tmp:
        registry = Registry(Path(tmp) / "state")
        keys = []
        for i in range(10):
            key = Path(tmp) / f"race{i}.json"
            write_key(generate_keypair(), key)
            keys.append(key)

        errors: list[Exception] = []

        def register(i: int) -> None:
            try:
                registry.register(keys[i], display_name=f"racer-{i}")
            except Exception as exc:  # noqa: BLE001 — surface thread failures
                errors.append(exc)

        threads = [threading.Thread(target=register, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors, errors
        assert len(registry.agents()) == 10


def test_head_anchor_detects_tail_truncation():
    """A truncated chain is internally consistent — only an external head
    anchor catches it (audit round 8 integrity assault finding)."""
    with tempfile.TemporaryDirectory() as tmp:
        registry, _, buyer_key, seller_did, _ = setup_world(tmp)
        for _ in range(3):
            registry.attest(seller_did, "task_completed", key_file=buyer_key)
        anchor = registry.head()
        assert anchor["length"] == 3 and len(anchor["head"]) == 64

        # drop the newest record: bare verify() cannot see it...
        lines = registry.log_path.read_text(encoding="utf-8").splitlines()
        registry.log_path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
        assert registry.verify()["ok"] is True  # the honest limitation

        # ...but the anchored verify can
        report = registry.verify(expected_head=anchor["head"])
        assert not report["ok"]
        assert any(p["issue"] == "head_anchor_mismatch" for p in report["problems"])
        report = registry.verify(expected_length=anchor["length"])
        assert not report["ok"]
        assert any(p["issue"] == "length_anchor_mismatch" for p in report["problems"])

        # a healthy chain passes the anchored check untouched
        grown = registry.verify(expected_head=registry.head()["head"])
        assert grown["ok"]


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
