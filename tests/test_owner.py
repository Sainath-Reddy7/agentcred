"""Tests for owner (principal) binding and lost-key recovery (v0.8).

Runs under pytest, or standalone: python tests/test_owner.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agentcred.crypto import generate_keypair, write_key  # noqa: E402
from agentcred.registry import Registry  # noqa: E402


def setup(tmp: str):
    agent_key = Path(tmp) / "agent.json"
    owner_key = Path(tmp) / "owner.json"
    buyer_key = Path(tmp) / "buyer.json"
    for path in (agent_key, owner_key, buyer_key):
        write_key(generate_keypair(), path)
    return agent_key, owner_key, buyer_key


def newkey(tmp: str, name: str) -> Path:
    path = Path(tmp) / name
    write_key(generate_keypair(), path)
    return path


def test_owner_binding_at_registration():
    with tempfile.TemporaryDirectory() as tmp:
        agent_key, owner_key, _ = setup(tmp)
        registry = Registry(Path(tmp) / "state")
        agent = registry.register(agent_key, display_name="shop-bot", owner_key_file=owner_key)

        assert agent["owner"] != agent["did"]  # genuinely owned, not self-owned
        assert agent["owner_key"] is not None
        kinds = [r.entry.get("kind") for r in registry._records()]
        assert kinds == ["owner.bound"]
        assert registry.verify()["ok"]


def test_owner_key_binds_only_one_identity():
    with tempfile.TemporaryDirectory() as tmp:
        agent_key, owner_key, _ = setup(tmp)
        registry = Registry(Path(tmp) / "state")
        registry.register(agent_key, owner_key_file=owner_key)
        other = newkey(tmp, "other.json")
        try:
            registry.register(other, owner_key_file=owner_key)
            raise AssertionError("one owner key bound two identities")
        except ValueError:
            pass


def test_lost_key_recovery_via_owner():
    with tempfile.TemporaryDirectory() as tmp:
        agent_key, owner_key, buyer_key = setup(tmp)
        registry = Registry(Path(tmp) / "state")
        agent = registry.register(agent_key, display_name="bot", owner_key_file=owner_key)
        registry.register(buyer_key, display_name="buyer")
        registry.attest(agent["did"], "task_completed", key_file=buyer_key)

        # agent key is LOST: only the owner can rotate in a replacement
        v2 = newkey(tmp, "agent-v2.json")
        identity = registry.rotate(agent["did"], key_file=owner_key, new_key_file=v2)
        assert identity["version"] == 2
        att = registry.attest(agent["did"], "task_completed", key_file=v2)
        assert att.id
        try:
            registry.attest(agent["did"], "task_completed", key_file=agent_key)
            raise AssertionError("lost key still works after owner rotation")
        except ValueError:
            pass
        assert registry.verify()["ok"]


def test_self_rotation_still_works_for_owned_agent():
    with tempfile.TemporaryDirectory() as tmp:
        agent_key, owner_key, _ = setup(tmp)
        registry = Registry(Path(tmp) / "state")
        agent = registry.register(agent_key, owner_key_file=owner_key)
        v2 = newkey(tmp, "v2.json")
        identity = registry.rotate(agent["did"], key_file=agent_key, new_key_file=v2)
        assert identity["version"] == 2
        assert registry.verify()["ok"]


def test_owner_revocation_without_agent_key():
    with tempfile.TemporaryDirectory() as tmp:
        agent_key, owner_key, buyer_key = setup(tmp)
        registry = Registry(Path(tmp) / "state")
        agent = registry.register(agent_key, owner_key_file=owner_key)
        registry.revoke(agent["did"], key_file=owner_key)
        assert "revoked" in registry.query(agent["did"])["flags"]


def test_strangers_have_no_authority():
    with tempfile.TemporaryDirectory() as tmp:
        agent_key, owner_key, buyer_key = setup(tmp)
        registry = Registry(Path(tmp) / "state")
        agent = registry.register(agent_key, owner_key_file=owner_key)
        v2 = newkey(tmp, "v2.json")
        for action in (
            lambda: registry.revoke(agent["did"], key_file=buyer_key),
            lambda: registry.rotate(agent["did"], key_file=buyer_key, new_key_file=v2),
        ):
            try:
                action()
                raise AssertionError("stranger exercised owner authority")
            except ValueError:
                pass


def test_owner_rotation_rejected_for_self_owned_agent():
    with tempfile.TemporaryDirectory() as tmp:
        agent_key, owner_key, _ = setup(tmp)
        registry = Registry(Path(tmp) / "state")
        agent = registry.register(agent_key)  # no owner
        v2 = newkey(tmp, "v2.json")
        try:
            registry.rotate(agent["did"], key_file=owner_key, new_key_file=v2)
            raise AssertionError("owner authority used on a self-owned identity")
        except ValueError:
            pass


def test_self_owned_agents_unchanged():
    with tempfile.TemporaryDirectory() as tmp:
        agent_key, _, buyer_key = setup(tmp)
        registry = Registry(Path(tmp) / "state")
        agent = registry.register(agent_key)
        registry.register(buyer_key)
        assert agent["owner"] == agent["did"]
        assert agent["owner_key"] is None
        registry.attest(agent["did"], "task_completed", key_file=buyer_key)
        assert registry.verify()["ok"]


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
