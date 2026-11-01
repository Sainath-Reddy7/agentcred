"""Tests for Ed25519 signing and verification (v0.2).

Runs under pytest, or standalone: python tests/test_crypto.py
Requires pynacl: pip install agentcred[crypto]
"""

from __future__ import annotations

import sys
from pathlib import Path

import nacl.exceptions

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agentcred.canonical import canonical  # noqa: E402
from agentcred.crypto import (  # noqa: E402
    did_from_jwk,
    generate_keypair,
    public_jwk,
    read_key,
    sign,
    sign_attestation,
    signing_key_from_jwk,
    verify,
    verify_attestation,
    write_key,
)
from agentcred.models import Attestation  # noqa: E402

AGENT = "did:agentcred:agent1"
OTHER = "did:agentcred:counterparty1"


def sample_attestation() -> Attestation:
    return Attestation(
        id="att_001",
        agent=AGENT,
        attester=OTHER,
        type="task_completed",
        signed_at="2026-11-01T00:00:00Z",
        payload={"task": "invoice-processing", "value_usd": 42.5},
    )


def test_sign_verify_roundtrip():
    jwk = generate_keypair()
    sig = sign(canonical({"hello": "world"}), jwk)
    verify(canonical({"hello": "world"}), sig, jwk)  # no exception = pass


def test_tampered_message_is_rejected():
    jwk = generate_keypair()
    sig = sign(canonical({"amount": 10}), jwk)
    try:
        verify(canonical({"amount": 100}), sig, jwk)
    except nacl.exceptions.BadSignatureError:
        pass
    else:
        raise AssertionError("tampered message verified — should have raised")


def test_wrong_key_is_rejected():
    signer = generate_keypair()
    other = generate_keypair()
    sig = sign(b"payload", signer)
    try:
        verify(b"payload", sig, other)
    except nacl.exceptions.BadSignatureError:
        pass
    else:
        raise AssertionError("signature verified under wrong key")


def test_attestation_sign_and_verify_roundtrip():
    attester_jwk = generate_keypair()
    att = sign_attestation(sample_attestation(), attester_jwk)
    assert att.signature
    verify_attestation(att, attester_jwk)


def test_unsigned_attestation_rejected():
    try:
        verify_attestation(sample_attestation(), generate_keypair())
    except ValueError:
        pass
    else:
        raise AssertionError("unsigned attestation passed verification")


def test_key_file_roundtrip_and_deterministic_did(tmp_path=None):
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        key_path = Path(tmp) / "attester.json"
        jwk = generate_keypair()
        write_key(jwk, key_path)
        loaded = read_key(key_path)
        assert loaded == jwk
        assert jwk["d"] not in public_jwk(signing_key_from_jwk(loaded)).values()
        did = did_from_jwk(loaded)
        assert did.startswith("did:agentcred:")
        assert did == did_from_jwk(loaded)  # content-derived, stable


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
