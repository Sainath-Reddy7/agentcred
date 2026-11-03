"""Tests for owner-key rotation (v0.5).

Runs under pytest, or standalone: python tests/test_rotation.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agentcred.crypto import generate_keypair, write_key  # noqa: E402
from agentcred.registry import Registry  # noqa: E402


def setup_world(tmp: str):
    seller_key = Path(tmp) / "seller.json"
    buyer_key = Path(tmp) / "buyer.json"
    write_key(generate_keypair(), seller_key)
    write_key(generate_keypair(), buyer_key)
    registry = Registry(Path(tmp) / "state")
    seller = registry.register(seller_key, display_name="seller")
    buyer = registry.register(buyer_key, display_name="buyer")
    return registry, seller_key, buyer_key, seller["did"], buyer["did"]


def new_keyfile(tmp: str, name: str) -> Path:
    path = Path(tmp) / name
    write_key(generate_keypair(), path)
    return path


def test_rotation_happy_path():
    with tempfile.TemporaryDirectory() as tmp:
        (registry, seller_key, buyer_key, seller_did, _) = setup_world(tmp)
        new_key = new_keyfile(tmp, "seller-v2.json")

        identity = registry.rotate(seller_did, key_file=seller_key, new_key_file=new_key)
        assert identity["did"] == seller_did  # DID pinned
        assert identity["version"] == 2

        # new key can act: attest about the seller, and revoke the seller
        registry.attest(seller_did, "task_completed", key_file=new_key)
        # old key no longer resolves to any identity
        try:
            registry.attest(seller_did, "task_completed", key_file=seller_key)
            raise AssertionError("old key still attests after rotation")
        except ValueError:
            pass
        registry.revoke(seller_did, key_file=new_key)
        assert "revoked" in registry.query(seller_did)["flags"]


def test_rotation_requires_current_key():
    with tempfile.TemporaryDirectory() as tmp:
        (registry, seller_key, buyer_key, seller_did, _) = setup_world(tmp)
        new_key = new_keyfile(tmp, "seller-v2.json")
        try:
            registry.rotate(seller_did, key_file=buyer_key, new_key_file=new_key)
            raise AssertionError("rotated with someone else's key")
        except ValueError:
            pass


def test_rotation_rejects_key_already_owned():
    with tempfile.TemporaryDirectory() as tmp:
        (registry, seller_key, buyer_key, seller_did, buyer_did) = setup_world(tmp)
        try:
            registry.rotate(seller_did, key_file=seller_key, new_key_file=buyer_key)
            raise AssertionError("rotated onto another identity's key")
        except ValueError:
            pass


def test_rotation_record_on_chain_and_verifiable():
    with tempfile.TemporaryDirectory() as tmp:
        (registry, seller_key, _, seller_did, _) = setup_world(tmp)
        registry.attest(seller_did, "task_completed", key_file=seller_key)
        new_key = new_keyfile(tmp, "v2.json")
        registry.rotate(seller_did, key_file=seller_key, new_key_file=new_key)

        kinds = [r.entry.get("kind") for r in registry._records()]
        assert kinds.count("key.rotated") == 1

        report = registry.verify()
        assert report["ok"], report["problems"]
        # attestation + rotation record both verify (old key carried in-record)
        assert report["signatures_valid"] == 2

        # a second rotation chains on top of the first
        newer = new_keyfile(tmp, "v3.json")
        registry.rotate(seller_did, key_file=new_key, new_key_file=newer)
        assert registry.verify()["ok"]
        assert len([k for k in kinds if k == "key.rotated"]) == 1  # kinds list was pre-rotate
        assert sum(1 for r in registry._records() if r.entry.get("kind") == "key.rotated") == 2


def test_revoked_identity_cannot_rotate():
    with tempfile.TemporaryDirectory() as tmp:
        (registry, seller_key, _, seller_did, _) = setup_world(tmp)
        new_key = new_keyfile(tmp, "v2.json")
        registry.revoke(seller_did, key_file=seller_key)
        try:
            registry.rotate(seller_did, key_file=seller_key, new_key_file=new_key)
            raise AssertionError("revoked identity rotated")
        except ValueError:
            pass


def test_register_rejects_key_already_in_use():
    with tempfile.TemporaryDirectory() as tmp:
        (registry, seller_key, _, seller_did, _) = setup_world(tmp)
        try:
            registry.register(seller_key, display_name="copycat")
            raise AssertionError("same key registered as a second identity")
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
