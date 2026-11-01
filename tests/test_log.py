"""Tests for the hash-chained attestation log (v0.2).

Runs under pytest, or standalone: python tests/test_log.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agentcred.log import GENESIS, LogTamperError, append, load, verify_chain  # noqa: E402


def build_log(tmp: str, n: int = 3) -> Path:
    path = Path(tmp) / "log.jsonl"
    for i in range(n):
        append(path, {"kind": "attestation", "seq": i})
    return path


def test_append_and_load():
    with tempfile.TemporaryDirectory() as tmp:
        path = build_log(tmp)
        records = load(path)
        assert [r.index for r in records] == [0, 1, 2]
        assert records[0].prev == GENESIS
        assert records[1].prev == records[0].hash
        assert records[2].prev == records[1].hash


def test_chain_verifies_when_intact():
    with tempfile.TemporaryDirectory() as tmp:
        verify_chain(load(build_log(tmp)))  # silent = intact


def test_edited_history_is_detected():
    with tempfile.TemporaryDirectory() as tmp:
        path = build_log(tmp)
        lines = path.read_text(encoding="utf-8").splitlines()
        # forge the middle record's entry without recomputing its hash
        import json

        forged = json.loads(lines[1])
        forged["entry"]["seq"] = 999
        lines[1] = json.dumps(forged, separators=(",", ":"), sort_keys=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        try:
            verify_chain(load(path))
        except LogTamperError as exc:
            assert exc.index == 1
        else:
            raise AssertionError("forged record passed chain verification")


def test_deleted_record_is_detected():
    with tempfile.TemporaryDirectory() as tmp:
        path = build_log(tmp)
        lines = path.read_text(encoding="utf-8").splitlines()
        del lines[0]  # genesis record removed
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        try:
            verify_chain(load(path))
        except LogTamperError:
            pass
        else:
            raise AssertionError("truncated log passed chain verification")


def test_missing_log_is_empty():
    with tempfile.TemporaryDirectory() as tmp:
        assert load(Path(tmp) / "nope.jsonl") == []


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
