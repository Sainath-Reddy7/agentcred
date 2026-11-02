"""Reference HTTP registry API (v0.3).

Run: agentcred serve --state ./agentcred-state   (or uvicorn agentcred.api:create_app --factory)

Private keys never leave clients. Clients sign attestations locally per
spec §7 and submit them; the server verifies against registered public
keys and commits to the hash-chained log. Endpoints are documented in
spec §9. No authentication or rate limiting yet — this is a reference
deployment, not a production service (sybil-resistance is roadmap v0.3).
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import FastAPI, HTTPException
from nacl.exceptions import BadSignatureError
from pydantic import BaseModel

from . import __version__
from .canonical import canonical
from .crypto import verify
from .models import Attestation
from .registry import Registry

FUTURE_TOLERANCE = timedelta(minutes=5)


class RegisterBody(BaseModel):
    public_jwk: dict
    display_name: str | None = None
    capabilities: list[str] = []


class RevokeBody(BaseModel):
    signature: str


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


def create_app(state_dir: str | None = None) -> FastAPI:
    """Build the registry app. State directory resolution: explicit
    argument, then AGENTCRED_STATE, then ./agentcred-state."""
    if state_dir is None:
        state_dir = os.environ.get("AGENTCRED_STATE", "agentcred-state")
    app = FastAPI(
        title="AgentCred registry",
        version=__version__,
        description="A credit bureau for AI agents — identity, attestations, trust scores.",
    )
    app.state.registry = Registry(state_dir)

    def reg() -> Registry:
        return app.state.registry

    @app.get("/")
    def index() -> dict[str, Any]:
        return {
            "name": "agentcred",
            "version": __version__,
            "endpoints": [
                "POST /agents — register an identity (public JWK)",
                "GET /agents/{did} — identity + trust score",
                "GET /agents/{did}/attestations — raw history",
                "POST /attestations — submit a signed attestation",
                "POST /disputes — open a dispute over an attestation (signed)",
                "POST /disputes/{id}/resolve — resolve (mutual or arbiter signatures)",
                "GET /disputes/{id} — dispute view",
                "GET /disputes/{id}/evidence — portable evidence bundle",
                "POST /agents/{did}/revoke — revoke (signature over revocation intent)",
                "GET /verify — log chain + signature report",
                "GET /health",
            ],
        }

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"ok": True, "version": __version__}

    @app.post("/agents", status_code=201)
    def register(body: RegisterBody) -> dict:
        try:
            return reg().register_jwk(
                body.public_jwk,
                display_name=body.display_name,
                capabilities=tuple(body.capabilities),
            )
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(400, f"public_jwk missing field {exc}") from exc

    @app.get("/agents/{did}")
    def query(did: str) -> dict:
        try:
            return reg().query(did)
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/agents/{did}/attestations")
    def history(did: str) -> dict:
        if reg().identity(did) is None:
            raise HTTPException(404, f"unknown agent {did}")
        return {
            "agent": did,
            "attestations": [att.to_dict() for att in reg().attestations_for(did)],
        }

    @app.post("/attestations", status_code=201)
    def attest(body: dict) -> dict:
        try:
            att = Attestation.from_dict(
                {
                    "id": body["id"],
                    "agent": body["agent"],
                    "attester": body["attester"],
                    "type": body["type"],
                    "signed_at": body["signed_at"],
                    "payload": body.get("payload", {}),
                    "signature": body.get("signature"),
                }
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise HTTPException(400, f"invalid attestation: {exc}") from exc
        if not att.signature:
            raise HTTPException(400, "attestation must be signed (spec §7)")
        try:
            when = _parse_ts(att.signed_at)
        except ValueError as exc:
            raise HTTPException(400, "signed_at must be ISO-8601 UTC") from exc
        if when > datetime.now(timezone.utc) + FUTURE_TOLERANCE:
            raise HTTPException(400, "signed_at is too far in the future")

        try:
            committed = reg().record(att)
        except BadSignatureError as exc:
            raise HTTPException(400, f"signature does not verify: {exc}") from exc
        except ValueError as exc:
            message = str(exc)
            if "unknown agent" in message or "not registered" in message:
                code = 404
            elif "revoked" in message:
                code = 409
            else:
                code = 400
            raise HTTPException(code, message) from exc
        return {"recorded": committed.id, "attestation": committed.to_dict()}

    @app.post("/agents/{did}/revoke")
    def revoke(did: str, body: RevokeBody) -> dict:
        identity = reg().identity(did)
        if identity is None:
            raise HTTPException(404, f"unknown agent {did}")
        if identity["revoked"]:
            raise HTTPException(409, f"{did} is already revoked")
        message = canonical({"action": "revoke", "agent": did})
        try:
            verify(message, body.signature, identity["public_key"])
        except (BadSignatureError, ValueError) as exc:
            raise HTTPException(
                400, "revocation signature does not verify for this identity"
            ) from exc
        return reg().revoke_identity(did)

    @app.post("/disputes", status_code=201)
    def open_dispute(body: dict) -> dict:
        """Client-signed dispute opening. The core (everything except
        `signature`) is exactly what the opener signs (spec §10)."""
        signature = body.get("signature")
        core = {
            "kind": "dispute.opened",
            "id": body.get("id"),
            "target": body.get("target"),
            "agent": body.get("agent"),
            "opened_by": body.get("opened_by"),
            "reason": body.get("reason", ""),
            "opened_at": body.get("opened_at"),
            "arbiter": body.get("arbiter"),
        }
        if not signature:
            raise HTTPException(400, "dispute.opened must carry a signature (spec §10)")
        try:
            entry = reg().commit_open_dispute(core, [signature])
        except BadSignatureError as exc:
            raise HTTPException(400, f"opening signature does not verify: {exc}") from exc
        except ValueError as exc:
            message = str(exc)
            if "unknown" in message and "target" not in message:
                code = 404
            elif "revoked" in message:
                code = 409
            else:
                code = 400
            raise HTTPException(code, message) from exc
        return {"opened": core["id"], "record": entry}

    @app.post("/disputes/{dispute_id}/resolve", status_code=201)
    def resolve_dispute(dispute_id: str, body: dict) -> dict:
        """Resolution with paired signatures. Mutual mode needs the opener
        and the disputed agent; arbiter mode needs the nominated arbiter."""
        core = {
            "kind": "dispute.resolved",
            "dispute": dispute_id,
            "outcome": body.get("outcome"),
            "resolved_by": body.get("resolved_by", []),
            "resolved_at": body.get("resolved_at"),
        }
        signatures = body.get("signatures", [])
        if not signatures:
            raise HTTPException(400, "resolution must carry signatures (paired with resolved_by)")
        try:
            entry = reg().commit_resolution(core, signatures)
        except BadSignatureError as exc:
            raise HTTPException(400, f"resolution signature does not verify: {exc}") from exc
        except ValueError as exc:
            message = str(exc)
            if "unknown" in message:
                code = 404
            elif "revoked" in message or "already resolved" in message:
                code = 409
            else:
                code = 400
            raise HTTPException(code, message) from exc
        return {"resolved": dispute_id, "outcome": core["outcome"], "record": entry}

    @app.get("/disputes/{dispute_id}")
    def dispute_view(dispute_id: str) -> dict:
        try:
            return reg().dispute_view(dispute_id)
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/disputes/{dispute_id}/evidence")
    def dispute_evidence(dispute_id: str) -> dict:
        try:
            return reg().evidence_bundle(dispute_id)
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/verify")
    def verify_registry() -> dict:
        return reg().verify()

    return app
