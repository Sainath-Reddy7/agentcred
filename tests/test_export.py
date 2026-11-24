"""Tests for full-registry export/import (v0.8.2).

Runs under pytest, or standalone: python tests/test_export.py
"""

from __future__ import annotations

import copy
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agentcred.crypto import generate_keypair, write_key  # noqa: E402
from agentcred.export import verify_export_state  # noqa: E402
from agentcred.registry import Registry  # noqa: E402


def build_rich_world(tmp: str):
    """A registry exercising every record kind: attestations, dispute,
    deal, rotation, owner binding, revocation."""
    keys = {}
    for name in ("seller", "buyer", "arbiter", "owner", "victim", "killer"):
        keys[name] = Path(tmp) / f"{name}.json"
        write_key(generate_keypair(), keys[name])

    registry = Registry(Path(tmp) / "state")
    seller = registry.register(keys["seller"], display_name="seller",
                               owner_key_file=keys["owner"])
    buyer = registry.register(keys["buyer"], display_name="buyer")
    registry.register(keys["arbiter"], display_name="arbiter")
    victim = registry.register(keys["victim"], display_name="victim")
    killer = registry.register(keys["killer"], display_name="killer")

    att = registry.attest(seller["did"], "task_completed", key_file=keys["buyer"],
                          payload={"value_usd": 250.0})
    dsp = registry.open_dispute(att.id, "quality", key_file=keys["buyer"])["id"]
    registry.resolve_dispute(dsp, "rejected", key_files=[keys["buyer"], keys["seller"]])
    deal = registry.open_deal(payee=seller["did"], amount_usd=100.0,
                              condition_type="task_completed",
                              payer_key_file=keys["buyer"], payee_key_file=keys["seller"])
    bound = registry.attest(seller["did"], "task_completed", key_file=keys["buyer"],
                            payload={"deal": deal["id"]})
    registry.settle_deal(deal["id"], bound.id, key_file=keys["buyer"])
    registry.revoke(killer["did"], key_file=keys["killer"])
    return registry, keys, seller, victim


def test_roundtrip_and_tamper_rejection():
    with tempfile.TemporaryDirectory() as tmp:
        registry, keys, seller, victim = build_rich_world(tmp)
        bundle = registry.export_state()

        clean = verify_export_state(bundle)
        assert clean["ok"], clean["problems"]
        assert clean["records"] > 0 and clean["identities"] == 5

        # restore into a fresh registry and keep working
        restored = Registry(Path(tmp) / "restored")
        report = restored.import_state(copy.deepcopy(bundle))
        assert report["ok"]
        assert restored.head() == registry.head()
        query = restored.query(seller["did"])
        assert query["identity"]["display_name"] == "seller"
        att2 = restored.attest(seller["did"], "task_completed", key_file=keys["buyer"])
        assert att2.id and restored.verify()["ok"]

        # 1. tampered record
        bad = copy.deepcopy(bundle)
        bad["records"][0]["entry"]["payload"] = {"task": "forged"}
        assert not verify_export_state(bad)["ok"]

        # 2. truncated tail with matching anchor claim
        bad = copy.deepcopy(bundle)
        bad["records"] = bad["records"][:-1]
        assert not verify_export_state(bad)["ok"]  # anchor mismatch

        # 3. owner tamper: grant a different owner key to the bound identity
        bad = copy.deepcopy(bundle)
        evil = generate_keypair()
        bad["identities"][seller["did"]]["owner_key"] = {
            k: evil[k] for k in ("kty", "crv", "x")
        }
        report = verify_export_state(bad)
        assert not report["ok"]
        assert any(p["issue"] == "owner_tampered" for p in report["problems"])

        # 4. un-revocation: flip state, chain still carries agent.revoked
        bad = copy.deepcopy(bundle)
        killer_did = next(
            did for did, i in bad["identities"].items() if i["display_name"] == "killer"
        )
        bad["identities"][killer_did]["revoked"] = False
        report = verify_export_state(bad)
        assert any(p["issue"] == "revocation_state_divergence" for p in report["problems"])

        # 5. dropped identity still referenced by records → flagged
        bad = copy.deepcopy(bundle)
        bad["identities"].pop(seller["did"], None)
        report = verify_export_state(bad)
        assert any(p["issue"] == "unknown_identity" for p in report["problems"])

        # documented blind spot: an identity with NO history is export-trusted —
        # dropping unreferenced victim is not (and cannot be) flagged
        bad = copy.deepcopy(bundle)
        bad["identities"].pop(victim["did"], None)
        assert verify_export_state(bad)["ok"]


def test_import_refuses_tampered_and_nonempty():
    with tempfile.TemporaryDirectory() as tmp:
        registry, _, _, _ = build_rich_world(tmp)
        bundle = registry.export_state()

        tampered = copy.deepcopy(bundle)
        tampered["records"][0]["entry"]["payload"] = {"x": 1}
        target = Registry(Path(tmp) / "t1")
        try:
            target.import_state(tampered)
            raise AssertionError("tampered export imported")
        except ValueError:
            pass

        good_target = Registry(Path(tmp) / "t2")
        good_target.import_state(copy.deepcopy(bundle))
        try:
            good_target.import_state(copy.deepcopy(bundle))
            raise AssertionError("import over a non-empty registry without force")
        except ValueError:
            pass
        good_target.import_state(copy.deepcopy(bundle), force=True)  # force works


def test_export_via_api_and_client():
    from fastapi.testclient import TestClient

    from agentcred.api import create_app
    from agentcred.client import RemoteRegistry
    from uvicorn import Config, Server
    import threading, socket, time

    with tempfile.TemporaryDirectory() as tmp:
        registry, keys, seller, _ = build_rich_world(tmp)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        server = Server(Config(create_app(str(Path(tmp) / "state")),
                               host="127.0.0.1", port=port, log_level="warning"))
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.1)
        try:
            remote = RemoteRegistry(f"http://127.0.0.1:{port}")
            pulled = remote.export()
            assert verify_export_state(pulled)["ok"]
            assert TestClient  # noqa: B018 — imported for API smoke parity
            restored = Registry(Path(tmp) / "restored2")
            restored.import_state(pulled)
            assert restored.head() == registry.head()
        finally:
            server.should_exit = True
            thread.join(timeout=5)


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
            except Exception as exc:  # noqa: BLE001
                failures += 1
                print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    sys.exit(1 if failures else 0)
