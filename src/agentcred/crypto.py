"""Ed25519 signing and verification (v0.2).

The signing input is the canonical JSON encoding of an attestation's
unsigned fields (see canonical.py). Signatures are detached, stored
base64url-encoded without padding in the attestation's `signature` field.

Keys are Ed25519 JWKs. Private key files additionally carry the 32-byte
seed in `d`. Requires the optional crypto extra: `pip install agentcred[crypto]`.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import nacl.exceptions
import nacl.signing

from .canonical import canonical
from .models import Attestation


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def generate_keypair() -> dict:
    """Generate an Ed25519 keypair; returns a private JWK (includes `d`)."""
    signing_key = nacl.signing.SigningKey.generate()
    jwk = public_jwk(signing_key)
    jwk["d"] = _b64u(bytes(signing_key))
    return jwk


def public_jwk(signing_key: nacl.signing.SigningKey) -> dict:
    verify_key = signing_key.verify_key
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64u(bytes(verify_key))}


def signing_key_from_jwk(jwk: dict) -> nacl.signing.SigningKey:
    return nacl.signing.SigningKey(_b64u_decode(jwk["d"]))


def verify_key_from_jwk(jwk: dict) -> nacl.signing.VerifyKey:
    return nacl.signing.VerifyKey(_b64u_decode(jwk["x"]))


def write_key(jwk: dict, path: str | Path) -> None:
    Path(path).write_text(json.dumps(jwk, indent=2), encoding="utf-8")


def read_key(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def sign(message: bytes, private_jwk: dict) -> str:
    """Sign raw bytes; returns the detached signature, base64url (unpadded)."""
    signed = signing_key_from_jwk(private_jwk).sign(message)
    return _b64u(signed.signature)


def verify(message: bytes, signature_b64: str, jwk: dict) -> None:
    """Verify a detached signature. Raises on tamper or wrong key.

    Raises nacl.exceptions.BadSignatureError for forged or mismatched
    signatures; ValueError for malformed key material.
    """
    verify_key_from_jwk(jwk).verify(message, _b64u_decode(signature_b64))


def sign_attestation(attestation: Attestation, private_jwk: dict) -> Attestation:
    """Return a copy of the attestation carrying an Ed25519 signature over
    the canonical form of its unsigned fields."""
    signature = sign(canonical(attestation.unsigned_dict()), private_jwk)
    return attestation.__class__(**{**attestation.__dict__, "signature": signature})


def verify_attestation(attestation: Attestation, jwk: dict) -> None:
    """Verify an attestation's signature against the attester's public JWK.

    Raises ValueError if the attestation is unsigned, nacl's
    BadSignatureError if the signature does not match.
    """
    if not attestation.signature:
        raise ValueError(f"attestation {attestation.id} is unsigned")
    verify(canonical(attestation.unsigned_dict()), attestation.signature, jwk)


def did_from_jwk(jwk: dict) -> str:
    """Content-derived agent DID: 12 hex chars of SHA-256 over the public key."""
    import hashlib

    digest = hashlib.sha256(_b64u_decode(jwk["x"])).hexdigest()[:12]
    return f"did:agentcred:{digest}"


__all__ = [
    "Any",
    "generate_keypair",
    "public_jwk",
    "signing_key_from_jwk",
    "verify_key_from_jwk",
    "write_key",
    "read_key",
    "sign",
    "verify",
    "sign_attestation",
    "verify_attestation",
    "did_from_jwk",
    "nacl",
]
