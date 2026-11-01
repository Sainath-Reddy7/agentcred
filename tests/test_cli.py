"""End-to-end CLI smoke tests (v0.2).

Runs under pytest, or standalone: python tests/test_cli.py
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agentcred.cli import main  # noqa: E402
from agentcred.crypto import did_from_jwk, read_key  # noqa: E402


def run(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(list(argv))
    return code, out.getvalue()


def test_full_workflow():
    with tempfile.TemporaryDirectory() as tmp:
        state = str(Path(tmp) / "state")
        seller_key = str(Path(tmp) / "seller.json")
        buyer_key = str(Path(tmp) / "buyer.json")

        assert run("--state", state, "keygen", "--out", seller_key)[0] == 0
        assert run("--state", state, "keygen", "--out", buyer_key)[0] == 0

        code, out = run("--state", state, "register", "--key", seller_key,
                        "--name", "invoice-bot", "--caps", "invoices.parse")
        assert code == 0
        seller_did = json.loads(out)["did"]
        assert seller_did == did_from_jwk(read_key(seller_key))

        assert run("--state", state, "register", "--key", buyer_key, "--name", "payer-bot")[0] == 0

        assert run("--state", state, "attest", "--key", buyer_key, "--agent", seller_did,
                   "--type", "payment_settled",
                   "--payload", '{"value_usd": 120.00}')[0] == 0

        code, out = run("--state", state, "query", "--agent", seller_did)
        assert code == 0
        result = json.loads(out)
        assert result["metrics"]["volume_usd"] == 120.0
        assert result["band"] == "E" or result["score"] >= 300

        code, out = run("--state", state, "verify")
        assert code == 0
        report = json.loads(out)
        assert report["ok"] and report["signatures_valid"] == 1

        code, out = run("--state", state, "log", "--agent", seller_did)
        assert code == 0 and "payment_settled" in out


def test_error_exit_codes():
    with tempfile.TemporaryDirectory() as tmp:
        state = str(Path(tmp) / "state")
        key = str(Path(tmp) / "k.json")
        run("--state", state, "keygen", "--out", key)
        code = run("--state", state, "attest", "--key", key,
                   "--agent", "did:agentcred:missing", "--type", "task_completed")[0]
        assert code == 2  # unregistered attester/agent → usage-style error


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
