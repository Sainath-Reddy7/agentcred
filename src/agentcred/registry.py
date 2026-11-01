"""File-backed reference registry (v0.2).

State layout inside the state directory:

    agents.json    {did: identity dict}  — public registry of identities
    log.jsonl      hash-chained attestation log (see log.py)

The attester of any attestation must itself be registered so that
`verify` can resolve its public key. Owner binding beyond the key itself
arrives with v0.3 key rotation.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from nacl.exceptions import BadSignatureError

from .crypto import did_from_jwk, read_key, sign_attestation, verify_attestation
from .log import LogTamperError, append, load, verify_chain
from .models import Attestation
from .scoring import score_agent


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Registry:
    def __init__(self, state_dir: str | Path = "agentcred-state"):
        self.dir = Path(state_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.agents_path = self.dir / "agents.json"
        self.log_path = self.dir / "log.jsonl"

    # -- identities -----------------------------------------------------

    def _load_agents(self) -> dict:
        if self.agents_path.exists():
            return json.loads(self.agents_path.read_text(encoding="utf-8"))
        return {}

    def _save_agents(self, agents: dict) -> None:
        self.agents_path.write_text(json.dumps(agents, indent=2), encoding="utf-8")

    def register(
        self,
        key_file: str | Path,
        display_name: str | None = None,
        capabilities: tuple[str, ...] = (),
    ) -> dict:
        return self.register_jwk(
            read_key(key_file), display_name=display_name, capabilities=capabilities
        )

    def register_jwk(
        self,
        jwk: dict,
        display_name: str | None = None,
        capabilities: tuple[str, ...] = (),
    ) -> dict:
        """Register an identity from a JWK (private file or public-only)."""
        did = did_from_jwk(jwk)
        agents = self._load_agents()
        if did in agents:
            raise ValueError(f"{did} is already registered")
        identity = {
            "did": did,
            "owner": did,  # self-owned until v0.3 owner-key binding
            "display_name": display_name or did,
            "capabilities": list(capabilities),
            "public_key": {k: jwk[k] for k in ("kty", "crv", "x")},
            "created_at": _now(),
            "revoked": False,
            "version": 1,
        }
        agents[did] = identity
        self._save_agents(agents)
        return identity

    def identity(self, did: str) -> dict | None:
        return self._load_agents().get(did)

    def revoke(self, did: str, key_file: str | Path) -> dict:
        """Self-service, one-way revocation.

        Possession of the identity's private key is the authority to revoke
        it (owner-key binding arrives with v0.3 rotation). History is kept;
        the identity is excluded from new attestations in both directions.
        """
        jwk = read_key(key_file)
        holder = did_from_jwk(jwk)
        if holder != did:
            raise ValueError(f"key belongs to {holder}, not {did}")
        return self.revoke_identity(did)

    def revoke_identity(self, did: str) -> dict:
        """Apply revocation after authority has been established."""
        agents = self._load_agents()
        identity = agents.get(did)
        if identity is None:
            raise ValueError(f"unknown agent {did}")
        if identity["revoked"]:
            raise ValueError(f"{did} is already revoked")
        identity["revoked"] = True
        identity["revoked_at"] = _now()
        identity["version"] += 1
        agents[did] = identity
        self._save_agents(agents)
        return identity

    # -- attestations ---------------------------------------------------

    def attest(
        self,
        agent: str,
        type_: str,
        key_file: str | Path,
        payload: dict | None = None,
    ) -> Attestation:
        """Build, sign, and commit an attestation from an attester key file."""
        jwk = read_key(key_file)
        attestation = Attestation(
            id=f"att_{uuid.uuid4().hex[:12]}",
            agent=agent,
            attester=did_from_jwk(jwk),
            type=type_,
            signed_at=_now(),
            payload=payload or {},
        )
        return self.record(sign_attestation(attestation, jwk))

    def record(self, attestation: Attestation) -> Attestation:
        """Verify and commit a pre-signed counterparty attestation.

        Enforces: attester registered and not revoked, subject registered
        and not revoked, signature valid under the attester's registered
        public key. This is the trust boundary for submitted attestations
        (API path); the local CLI path funnels through it too.
        """
        agents = self._load_agents()
        if attestation.attester not in agents:
            raise ValueError(
                f"attester {attestation.attester} is not registered — register the key first"
            )
        if attestation.agent not in agents:
            raise ValueError(f"unknown agent {attestation.agent}")
        if agents[attestation.attester]["revoked"]:
            raise ValueError(f"attester {attestation.attester} is revoked")
        if agents[attestation.agent]["revoked"]:
            raise ValueError(f"agent {attestation.agent} is revoked")
        verify_attestation(
            attestation, agents[attestation.attester]["public_key"]
        )
        append(self.log_path, attestation.to_dict())
        return attestation

    def attestations_for(self, agent: str | None = None) -> list[Attestation]:
        records = load(self.log_path)
        if agent is None:
            return [Attestation.from_dict(r.entry) for r in records]
        return [
            Attestation.from_dict(r.entry)
            for r in records
            if r.entry.get("agent") == agent
        ]

    # -- queries --------------------------------------------------------

    def query(self, agent: str) -> dict:
        identity = self._load_agents().get(agent)
        if identity is None:
            raise ValueError(f"unknown agent {agent}")
        result = score_agent(self.attestations_for(agent))
        result["identity"] = identity
        if identity.get("revoked"):
            result["flags"].append("revoked")
        return result

    def verify(self) -> dict:
        """Walk the log: chain integrity + every signature against the
        registered attester key. Returns a report; `ok` is False on any
        problem."""
        problems: list[dict] = []
        chain = "ok"
        records = []
        try:
            records = load(self.log_path)
            verify_chain(records)
        except LogTamperError as exc:
            chain = f"broken at record {exc.index}: {exc.reason}"
            problems.append({"index": exc.index, "issue": "chain", "detail": str(exc)})

        agents = self._load_agents()
        valid = 0
        for record in records:
            att = Attestation.from_dict(record.entry)
            if att.agent not in agents:
                problems.append(
                    {"index": record.index, "issue": "unknown_agent", "detail": att.agent}
                )
                continue
            jwk = agents.get(att.attester, {}).get("public_key")
            if not jwk:
                problems.append(
                    {"index": record.index, "issue": "unknown_attester", "detail": att.attester}
                )
                continue
            try:
                verify_attestation(att, jwk)
                valid += 1
            except (BadSignatureError, ValueError) as exc:
                problems.append(
                    {"index": record.index, "issue": "bad_signature", "detail": str(exc)}
                )
        return {
            "ok": not problems,
            "chain": chain,
            "records": len(records),
            "signatures_valid": valid,
            "problems": problems,
        }
