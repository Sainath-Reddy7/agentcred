"""Reference HTTP client for AgentCred registries (v0.7).

Mirrors the local Registry's high-level surface over the §9 API. Private
keys never leave this process: everything that requires authority is
signed locally (canonical form, §7) and submitted. Stdlib only.

    from agentcred.client import RemoteRegistry
    remote = RemoteRegistry("https://registry.example.com")
    remote.register("keys/bot.json", display_name="invoice-bot")
    report = remote.query(did)

Or from the CLI: agentcred --url https://registry.example.com attest ...
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .canonical import canonical
from .crypto import did_from_jwk, read_key, sign


class ClientError(ValueError):
    """A registry rejected a request. Subclasses ValueError so the CLI's
    existing error handling maps it to a clean exit."""

    def __init__(self, status: int, message: str):
        self.status = status
        super().__init__(message)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _public(jwk: dict) -> dict:
    return {k: jwk[k] for k in ("kty", "crv", "x")}


class RemoteRegistry:
    def __init__(self, base_url: str, timeout: float = 15.0):
        self.base = base_url.rstrip("/")
        self.timeout = timeout  # a dead registry must fail fast, not hang the CLI

    # -- transport ------------------------------------------------------

    def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        data = canonical(body).decode("utf-8") if body is not None else None
        request = urllib.request.Request(
            self.base + path,
            data=data.encode("utf-8") if data is not None else None,
            method=method,
            headers={"content-type": "application/json"} if data is not None else {},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")
            try:
                detail = json.loads(detail).get("detail", detail)
            except (json.JSONDecodeError, ValueError):
                pass
            raise ClientError(exc.code, f"registry rejected ({exc.code}): {detail}") from None
        except TimeoutError as exc:
            raise ClientError(0, f"registry at {self.base} timed out after {self.timeout}s") from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise ClientError(0, f"registry at {self.base} timed out after {self.timeout}s") from exc
            raise ClientError(0, f"cannot reach registry at {self.base}: {exc.reason}") from None

    # -- identity -------------------------------------------------------

    def did_for_key(self, jwk: dict) -> str | None:
        """Which registered identity does this key belong to? Matches the
        public half, so it works across key rotations (v0.5)."""
        public = _public(jwk)
        for identity in self.agents():
            if identity["public_key"] == public:
                return identity["did"]
        return None

    def agents(self) -> list[dict]:
        return self._call("GET", "/agents")["agents"]

    def register(
        self,
        key_file: str | Path,
        display_name: str | None = None,
        capabilities: tuple[str, ...] = (),
        owner_key_file: str | Path | None = None,
    ) -> dict:
        jwk = read_key(key_file)
        body: dict = {
            "public_jwk": _public(jwk),
            "display_name": display_name,
            "capabilities": list(capabilities),
        }
        if owner_key_file is not None:
            owner_jwk = read_key(owner_key_file)
            owner_public = _public(owner_jwk)
            core = {
                "kind": "owner.bound",
                "agent": did_from_jwk(jwk),
                "owner": did_from_jwk(owner_jwk),
                "owner_public_jwk": owner_public,
                "bound_at": _now(),
            }
            body |= {
                "owner_public_jwk": owner_public,
                "bound_at": core["bound_at"],
                "owner_signature": sign(canonical(core), owner_jwk),
            }
        return self._call("POST", "/agents", body)

    def identity(self, agent: str) -> dict:
        return self.query(agent)["identity"]

    def revoke(self, did: str, key_file: str | Path) -> dict:
        jwk = read_key(key_file)
        public = _public(jwk)
        identity = self.identity(did)
        if identity["public_key"] == public:
            authority = "self"
        elif identity.get("owner_key") and identity["owner_key"] == public:
            authority = "owner"
        else:
            raise ClientError(0, f"key belongs neither to {did} nor to its owner")
        core = {
            "kind": "agent.revoked",
            "agent": did,
            "authority": authority,
            "revoked_at": _now(),
        }
        if authority == "owner":
            core["authority_public_jwk"] = public
        body = {k: core[k] for k in ("authority", "revoked_at")}
        if authority == "owner":
            body["authority_public_jwk"] = public
        body["signature"] = sign(canonical(core), jwk)
        return self._call("POST", f"/agents/{did}/revoke", body)

    def rotate(self, did: str, key_file: str | Path, new_key_file: str | Path) -> dict:
        old_jwk = read_key(key_file)
        new_jwk = read_key(new_key_file)
        core = {
            "kind": "key.rotated",
            "agent": did,
            "old_public_jwk": self.identity(did)["public_key"],
            "new_public_jwk": _public(new_jwk),
            "rotated_at": _now(),
        }
        self._call(
            "POST", f"/agents/{did}/rotate",
            {"old_public_jwk": core["old_public_jwk"],
             "new_public_jwk": core["new_public_jwk"],
             "rotated_at": core["rotated_at"],
             "signature": sign(canonical(core), old_jwk)},
        )
        return self.identity(did)

    # -- attestations ---------------------------------------------------

    def attest(
        self,
        agent: str,
        type_: str,
        key_file: str | Path,
        payload: dict | None = None,
    ) -> dict:
        jwk = read_key(key_file)
        attester = self.did_for_key(jwk)
        if attester is None:
            raise ClientError(0, "attester key is not registered — register the key first")
        unsigned = {
            "id": f"att_{uuid.uuid4().hex[:12]}",
            "agent": agent,
            "attester": attester,
            "type": type_,
            "signed_at": _now(),
            "payload": payload or {},
        }
        response = self._call(
            "POST", "/attestations", unsigned | {"signature": sign(canonical(unsigned), jwk)}
        )
        return response["attestation"]

    def attestation(self, attestation_id: str) -> dict:
        return self._call("GET", f"/attestations/{attestation_id}")

    def attestations_for(self, agent: str | None = None) -> list[dict]:
        if agent is None:
            raise ClientError(0, "remote attestations listing requires --agent")
        return self._call("GET", f"/agents/{agent}/attestations")["attestations"]

    def query(self, agent: str) -> dict:
        return self._call("GET", f"/agents/{agent}")

    def anchor(self) -> dict:
        return self._call("GET", "/anchor")

    def verify(self, expected_head: str | None = None, expected_length: int | None = None) -> dict:
        params = []
        if expected_head:
            params.append(f"expected_head={expected_head}")
        if expected_length is not None:
            params.append(f"expected_length={expected_length}")
        path = "/verify" + ("?" + "&".join(params) if params else "")
        return self._call("GET", path)

    # -- disputes -------------------------------------------------------

    def open_dispute(
        self,
        target: str,
        reason: str,
        key_file: str | Path,
        arbiter: str | None = None,
    ) -> dict:
        jwk = read_key(key_file)
        opener = self.did_for_key(jwk)
        if opener is None:
            raise ClientError(0, "opener key is not registered — register the key first")
        core = {
            "kind": "dispute.opened",
            "id": f"dsp_{uuid.uuid4().hex[:12]}",
            "target": target,
            "agent": self.attestation(target)["agent"],
            "opened_by": opener,
            "reason": reason,
            "opened_at": _now(),
            "arbiter": arbiter,
        }
        response = self._call("POST", "/disputes", core | {"signature": sign(canonical(core), jwk)})
        return response["record"]

    def resolve_dispute(
        self, dispute: str, outcome: str, key_files: list[str | Path]
    ) -> dict:
        jwks = [read_key(k) for k in key_files]
        resolved_by = []
        for jwk in jwks:
            did = self.did_for_key(jwk)
            if did is None:
                raise ClientError(0, "resolver key is not registered — register the key first")
            resolved_by.append(did)
        core = {
            "kind": "dispute.resolved",
            "dispute": dispute,
            "outcome": outcome,
            "resolved_by": resolved_by,
            "resolved_at": _now(),
        }
        signatures = [sign(canonical(core), jwk) for jwk in jwks]
        response = self._call(
            "POST", f"/disputes/{dispute}/resolve", core | {"signatures": signatures}
        )
        return response["record"]

    def disputes_for(self, agent: str | None = None) -> list[dict]:
        path = f"/disputes?agent={agent}" if agent else "/disputes"
        return self._call("GET", path)["disputes"]

    def evidence_bundle(self, dispute_id: str) -> dict:
        return self._call("GET", f"/disputes/{dispute_id}/evidence")

    # -- deals ----------------------------------------------------------

    def open_deal(
        self,
        payee: str,
        amount_usd: float,
        condition_type: str,
        payer_key_file: str | Path,
        payee_key_file: str | Path,
        terms: str = "",
        deadline: str | None = None,
        arbiter: str | None = None,
    ) -> dict:
        payer_jwk = read_key(payer_key_file)
        payee_jwk = read_key(payee_key_file)
        payee_did = self.did_for_key(payee_jwk)
        if payee is not None and payee != payee_did:
            raise ClientError(0, f"payee key belongs to {payee_did}, not {payee}")
        core = {
            "kind": "deal.opened",
            "id": f"deal_{uuid.uuid4().hex[:12]}",
            "payer": self.did_for_key(payer_jwk),
            "payee": payee_did,
            "amount_usd": amount_usd,
            "terms": terms,
            "condition_type": condition_type,
            "deadline": deadline,
            "arbiter": arbiter,
            "opened_at": _now(),
        }
        signatures = [sign(canonical(core), payer_jwk), sign(canonical(core), payee_jwk)]
        response = self._call("POST", "/deals", core | {"signatures": signatures})
        return response["record"]

    def settle_deal(self, deal: str, settlement: str, key_file: str | Path) -> dict:
        jwk = read_key(key_file)
        settled_by = self.did_for_key(jwk)
        if settled_by is None:
            raise ClientError(0, "settlement key is not registered — register the key first")
        core = {
            "kind": "deal.settled",
            "deal": deal,
            "settlement": settlement,
            "settled_by": settled_by,
            "settled_at": _now(),
        }
        response = self._call(
            "POST", f"/deals/{deal}/settle",
            {"settlement": settlement, "settled_by": settled_by,
             "settled_at": core["settled_at"], "signature": sign(canonical(core), jwk)},
        )
        return response["record"]

    def cancel_deal(
        self,
        deal: str,
        payer_key_file: str | Path,
        payee_key_file: str | Path,
        reason: str = "",
    ) -> dict:
        payer_jwk = read_key(payer_key_file)
        payee_jwk = read_key(payee_key_file)
        core = {
            "kind": "deal.cancelled",
            "deal": deal,
            "reason": reason,
            "cancelled_at": _now(),
        }
        signatures = [sign(canonical(core), payer_jwk), sign(canonical(core), payee_jwk)]
        response = self._call(
            "POST", f"/deals/{deal}/cancel", core | {"signatures": signatures}
        )
        return response["record"]

    def deals_for(self, agent: str | None = None) -> list[dict]:
        path = f"/deals?agent={agent}" if agent else "/deals"
        return self._call("GET", path)["deals"]

    def deal_view(self, deal_id: str) -> dict:
        return self._call("GET", f"/deals/{deal_id}")


__all__ = ["RemoteRegistry", "ClientError", "did_from_jwk"]
