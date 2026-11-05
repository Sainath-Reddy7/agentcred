"""Integration tests for the remote client (v0.7).

Boots a real uvicorn server on a free local port and drives the entire
protocol through RemoteRegistry and the CLI's --url mode. Keys are
generated and used locally only.

Runs under pytest, or standalone: python tests/test_client.py
"""

from __future__ import annotations

import contextlib
import io
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from uvicorn import Config, Server  # noqa: E402

from agentcred.client import ClientError, RemoteRegistry  # noqa: E402
from agentcred.crypto import generate_keypair, write_key  # noqa: E402


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Server:
    def __init__(self, state_dir: str):
        from agentcred.api import create_app

        self.port = _free_port()
        self.server = Server(
            Config(create_app(state_dir), host="127.0.0.1", port=self.port, log_level="warning")
        )
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self) -> str:
        self.thread.start()
        for _ in range(100):
            if self.server.started:
                return f"http://127.0.0.1:{self.port}"
            time.sleep(0.1)
        raise RuntimeError("server did not start")

    def __exit__(self, *exc) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=5)


def _keys(tmp: str, *names: str) -> dict[str, Path]:
    out = {}
    for name in names:
        path = Path(tmp) / f"{name}.json"
        write_key(generate_keypair(), path)
        out[name] = path
    return out


def test_remote_full_protocol():
    with tempfile.TemporaryDirectory() as tmp:
        with _Server(str(Path(tmp) / "state")) as base:
            remote = RemoteRegistry(base)
            keys = _keys(tmp, "seller", "buyer")

            seller = remote.register(keys["seller"], display_name="invoice-bot")
            buyer = remote.register(keys["buyer"], display_name="payer-bot")

            att = remote.attest(
                seller["did"], "task_completed", keys["buyer"],
                payload={"task": "invoices", "value_usd": 120.0},
            )
            assert remote.attestation(att["id"])["id"] == att["id"]
            report = remote.query(seller["did"])
            assert report["metrics"]["interactions"] == 1

            # court: dispute, mutual resolution, evidence
            opened = remote.open_dispute(att["id"], "not done properly", keys["buyer"])
            remote.resolve_dispute(opened["id"], "rejected", [keys["buyer"], keys["seller"]])
            views = remote.disputes_for(seller["did"])
            assert views[0]["outcome"] == "rejected"
            bundle = remote.evidence_bundle(opened["id"])
            assert bundle["format"] == "agentcred/evidence-bundle@1"

            # commerce: deal with attestation-gated settlement
            deal = remote.open_deal(
                payee=seller["did"], amount_usd=250.0, condition_type="task_completed",
                payer_key_file=keys["buyer"], payee_key_file=keys["seller"],
                terms="more invoices",
            )
            bound = remote.attest(
                seller["did"], "task_completed", keys["buyer"],
                payload={"deal": deal["id"], "value_usd": 250.0},
            )
            remote.settle_deal(deal["id"], bound["id"], keys["buyer"])
            assert remote.deal_view(deal["id"])["status"] == "settled"

            # lifecycle: rotate, then revoke with the NEW key
            keys["seller_v2"] = Path(tmp) / "seller_v2.json"
            write_key(generate_keypair(), keys["seller_v2"])
            identity = remote.rotate(seller["did"], keys["seller"], keys["seller_v2"])
            assert identity["version"] == 2
            remote.revoke(seller["did"], keys["seller_v2"])
            assert "revoked" in remote.query(seller["did"])["flags"]

            audit = remote.verify()
            assert audit["ok"], audit["problems"]
            assert {a["did"] for a in remote.agents()} == {seller["did"], buyer["did"]}
            assert len(remote.deals_for(seller["did"])) == 1


def test_remote_errors_surface_cleanly():
    with tempfile.TemporaryDirectory() as tmp:
        with _Server(str(Path(tmp) / "state")) as base:
            remote = RemoteRegistry(base)
            keys = _keys(tmp, "one")
            remote.register(keys["one"], display_name="solo")
            try:
                remote.query("did:agentcred:missing")
                raise AssertionError("unknown agent query succeeded")
            except ClientError as exc:
                assert "404" in str(exc) or exc.status == 404
            key2 = Path(tmp) / "stranger.json"
            write_key(generate_keypair(), key2)
            try:
                remote.attest("did:agentcred:x", "task_completed", key2)
                raise AssertionError("unregistered attester accepted")
            except ClientError:
                pass


def test_cli_url_mode():
    from agentcred.cli import main

    with tempfile.TemporaryDirectory() as tmp:
        with _Server(str(Path(tmp) / "state")) as base:
            keys = _keys(tmp, "a", "b")

            def run(*argv: str) -> int:
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    return main(["--url", base, *argv])

            assert run("keygen", "--out", str(keys["a"])) == 0  # offline op still fine
            assert run("register", "--key", str(keys["a"]), "--name", "bot-a") == 0
            assert run("register", "--key", str(keys["b"]), "--name", "bot-b") == 0

            did_a = [line.split()[0] for line in _capture_agents(base).splitlines() if "bot-a" in line][0]
            assert run("attest", "--key", str(keys["b"]), "--agent", did_a,
                       "--type", "task_completed") == 0
            assert run("query", "--agent", did_a) == 0
            assert run("verify") == 0
            assert run("disputes") == 0
            assert run("deals") == 0
            assert run("log", "--agent", did_a) == 0


def _capture_agents(base: str) -> str:
    import urllib.request

    with urllib.request.urlopen(base + "/agents") as response:
        agents = __import__("json").loads(response.read())["agents"]
    return "\n".join(f"{a['did']}  {a['display_name']}" for a in agents)


def test_client_times_out_fast():
    """A dead/black-hole registry must raise ClientError quickly, not hang."""
    import time as _time

    remote = RemoteRegistry("http://10.255.255.1:8000", timeout=1.0)  # non-routable
    started = _time.monotonic()
    try:
        remote.verify()
        raise AssertionError("black-hole registry responded?!")
    except ClientError as exc:
        assert "timed out" in str(exc) or "cannot reach" in str(exc)
    elapsed = _time.monotonic() - started
    assert elapsed < 10, f"took {elapsed:.1f}s to fail — effectively hanging"


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
