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
from datetime import datetime, timedelta, timezone
from pathlib import Path

from nacl.exceptions import BadSignatureError

from .canonical import canonical
from .crypto import did_from_jwk, read_key, sign, sign_attestation, verify, verify_attestation
from .locking import file_lock
from .log import LogTamperError, append, load, verify_chain
from .models import Attestation
from .scoring import score_agent

DISPUTE_OUTCOMES = frozenset({"upheld", "rejected", "settled"})
# Griefing containment (spec §10): while open, disputes count provisionally
# against the accused — so mass-opening must not be free.
MAX_OPEN_DISPUTES_PER_OPENER = 5
MAX_OPEN_DISPUTES_PER_TARGET = 3
# A deal's condition is proven by an attestation of one of these types
# (spec §11).
DEAL_CONDITION_TYPES = frozenset(
    {"task_completed", "payment_settled", "capability_verified"}
)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


TIMESTAMP_TOLERANCE = timedelta(minutes=5)


def _valid_ts(ts: object) -> bool:
    """ISO-8601 UTC, not further in the future than clock-skew tolerance."""
    try:
        when = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return False
    if when.tzinfo is None:
        return False
    return when <= datetime.now(timezone.utc) + TIMESTAMP_TOLERANCE


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
        owner_key_file: str | Path | None = None,
    ) -> dict:
        owner_bind = None
        if owner_key_file is not None:
            owner_jwk = read_key(owner_key_file)
            owner_public = {k: owner_jwk[k] for k in ("kty", "crv", "x")}
            core = {
                "kind": "owner.bound",
                "agent": did_from_jwk(read_key(key_file)),
                "owner": did_from_jwk(owner_jwk),
                "owner_public_jwk": owner_public,
                "bound_at": _now(),
            }
            owner_bind = {"core": core, "signature": sign(canonical(core), owner_jwk)}
        return self.register_jwk(
            read_key(key_file),
            display_name=display_name,
            capabilities=capabilities,
            owner_bind=owner_bind,
        )

    def did_for_key(self, jwk: dict) -> str | None:
        """Which registered identity does this key (private or public JWK)
        belong to? Matches on the public half, so it keeps working after
        key rotation — a rotated identity's DID no longer equals the
        content-DID of its current key."""
        public = {k: jwk[k] for k in ("kty", "crv", "x")}
        for did, identity in self._load_agents().items():
            if identity["public_key"] == public:
                return did
        return None

    def register_jwk(
        self,
        jwk: dict,
        display_name: str | None = None,
        capabilities: tuple[str, ...] = (),
        owner_bind: dict | None = None,
    ) -> dict:
        """Register an identity from a JWK (private file or public-only).

        With `owner_bind` (core + owner signature) the identity is bound
        to an accountable principal who can later revoke the agent and
        rotate a lost agent key (spec §2).
        """
        with file_lock(self.agents_path):
            did = did_from_jwk(jwk)
            agents = self._load_agents()
            public = {k: jwk[k] for k in ("kty", "crv", "x")}
            for existing in agents.values():
                if existing["public_key"] == public:
                    raise ValueError(f"key already registered as {existing['did']}")
            if did in agents:
                raise ValueError(f"{did} is already registered")
            identity = {
                "did": did,
                "owner": did,  # self-owned unless an owner binding says otherwise
                "display_name": display_name or did,
                "capabilities": list(capabilities),
                "public_key": {k: jwk[k] for k in ("kty", "crv", "x")},
                "created_at": _now(),
                "revoked": False,
                "version": 1,
                "owner_key": None,
            }
            if owner_bind is not None:
                core = owner_bind["core"]
                if core.get("kind") != "owner.bound":
                    raise ValueError("expected an owner.bound record")
                if core.get("agent") != did:
                    raise ValueError("owner binding names a different agent")
                if core.get("owner") != did_from_jwk(core.get("owner_public_jwk") or {}):
                    raise ValueError("owner did does not match owner_public_jwk")
                if not _valid_ts(core.get("bound_at")):
                    raise ValueError("bound_at must be ISO-8601 UTC, within clock-skew tolerance of now")
                try:
                    verify(
                        canonical(core), owner_bind["signature"], core["owner_public_jwk"]
                    )
                except BadSignatureError as exc:
                    raise ValueError(f"owner binding signature does not verify: {exc}") from exc
                if any(
                    other.get("owner_key") == core["owner_public_jwk"]
                    for other in agents.values()
                ):
                    raise ValueError("owner key already binds another identity")
                identity["owner"] = core["owner"]
                identity["owner_key"] = core["owner_public_jwk"]
            agents[did] = identity
            self._save_agents(agents)
            if owner_bind is not None:
                append(self.log_path, owner_bind["core"] | {"signatures": [owner_bind["signature"]]})
            return identity

    def identity(self, did: str) -> dict | None:
        return self._load_agents().get(did)

    def revoke(self, did: str, key_file: str | Path) -> dict:
        """Self-service, one-way revocation — now chain-recorded.

        Authority: the identity's current private key, or — for owner-bound
        identities — the owner's key (the recovery path when the agent key
        is lost or compromised). The revocation is committed to the chain
        as an `agent.revoked` record signed by that authority, so the kill
        switch is tamper-evident like every other transition.
        """
        jwk = read_key(key_file)
        public = {k: jwk[k] for k in ("kty", "crv", "x")}
        identity = self._load_agents().get(did)
        if identity is None:
            raise ValueError(f"unknown agent {did}")
        if identity["public_key"] == public:
            authority = "self"
        elif identity.get("owner_key") and identity["owner_key"] == public:
            authority = "owner"
        else:
            raise ValueError(f"key belongs neither to {did} nor to its owner")
        core = {
            "kind": "agent.revoked",
            "agent": did,
            "authority": authority,
            "revoked_at": _now(),
        }
        if authority == "owner":
            core["authority_public_jwk"] = public
        signature = sign(canonical(core), jwk)
        return self.commit_revocation_record(core, [signature])

    def commit_revocation_record(self, core: dict, signatures: list[str]) -> dict:
        """Verify and apply a pre-signed revocation (API path)."""
        with file_lock(self.agents_path):
            agents = self._load_agents()
            did = core.get("agent")
            identity = agents.get(did)
            if identity is None:
                raise ValueError(f"unknown agent {did}")
            if identity["revoked"]:
                raise ValueError(f"{did} is already revoked")
            if core.get("kind") != "agent.revoked":
                raise ValueError("expected an agent.revoked record")
            authority = core.get("authority")
            if authority not in ("self", "owner"):
                raise ValueError("authority must be 'self' or 'owner'")
            if not _valid_ts(core.get("revoked_at")):
                raise ValueError("revoked_at must be ISO-8601 UTC, within clock-skew tolerance of now")
            if authority == "owner":
                if not identity.get("owner_key"):
                    raise ValueError(f"{did} has no owner to revoke it")
                if core.get("authority_public_jwk") != identity["owner_key"]:
                    raise ValueError("authority_public_jwk does not match the bound owner")
                signing_key = core["authority_public_jwk"]
            else:
                signing_key = identity["public_key"]
            if len(signatures) != 1:
                raise ValueError("agent.revoked carries exactly one signature")
            try:
                verify(canonical(core), signatures[0], signing_key)
            except BadSignatureError as exc:
                raise ValueError(f"revocation signature does not verify: {exc}") from exc
            append(self.log_path, core | {"signatures": list(signatures)})
            identity["revoked"] = True
            identity["revoked_at"] = core["revoked_at"]
            identity["version"] += 1
            agents[did] = identity
            self._save_agents(agents)
            return identity

    def revoke_identity(self, did: str) -> dict:
        """Apply the revocation state change. Only meaningful after
        authority was established and the agent.revoked record committed;
        kept for direct internal use."""
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

    # -- key rotation (v0.5) ---------------------------------------------

    def rotate(self, did: str, key_file: str | Path, new_key_file: str | Path) -> dict:
        """Rotate an identity's key: old key authorizes, new key takes over.

        The DID stays pinned — it names the identity, not the key. The
        rotation is recorded on the chain as a `key.rotated` record signed
        by the OLD key, carrying the old public JWK so the record remains
        verifiable after the registry no longer knows that key.
        """
        old_jwk = read_key(key_file)
        new_jwk = read_key(new_key_file)
        authority_public = {k: old_jwk[k] for k in ("kty", "crv", "x")}
        identity = self._load_agents().get(did)
        if identity is None:
            raise ValueError(f"unknown agent {did}")
        if identity["public_key"] == authority_public:
            authority = "self"
        elif identity.get("owner_key") and identity["owner_key"] == authority_public:
            authority = "owner"  # lost-key recovery: the owner rotates the agent's key
        else:
            raise ValueError(f"key belongs neither to {did} nor to its owner")
        core = {
            "kind": "key.rotated",
            "agent": did,
            "authority": authority,
            "old_public_jwk": identity["public_key"],
            "new_public_jwk": {k: new_jwk[k] for k in ("kty", "crv", "x")},
            "rotated_at": _now(),
        }
        if authority == "owner":
            core["authority_public_jwk"] = authority_public
        signature = sign(canonical(core), old_jwk)
        self.commit_rotation_record(core, [signature])
        return self._load_agents()[did]

    def commit_rotation_record(self, core: dict, signatures: list[str]) -> dict:
        """Verify and apply a pre-signed key rotation (API path).

        Holds the agents-state lock across verify→chain-append→save so a
        concurrent register/revoke cannot interleave (the log lock nests
        inside; ordering is always state→log, so no deadlock).
        """
        with file_lock(self.agents_path):
            agents = self._load_agents()
            did = core.get("agent")
            identity = agents.get(did)
            if identity is None:
                raise ValueError(f"unknown agent {did}")
            if identity["revoked"]:
                raise ValueError(f"{did} is revoked")
            if core.get("kind") != "key.rotated":
                raise ValueError("expected a key.rotated record")
            for field in ("old_public_jwk", "new_public_jwk", "rotated_at"):
                if field not in core:
                    raise ValueError(f"key.rotated missing field {field}")
            authority = core.get("authority", "self")
            if authority not in ("self", "owner"):
                raise ValueError("authority must be 'self' or 'owner'")
            if authority == "owner":
                if not identity.get("owner_key"):
                    raise ValueError(f"{did} has no owner to rotate its key")
                if core.get("authority_public_jwk") != identity["owner_key"]:
                    raise ValueError("authority_public_jwk does not match the bound owner")
                signing_key = core["authority_public_jwk"]
            else:
                signing_key = identity["public_key"]
            if core["old_public_jwk"] != identity["public_key"]:
                raise ValueError("old_public_jwk does not match the registered key")
            if core["new_public_jwk"] == core["old_public_jwk"]:
                raise ValueError("new key equals the current key")
            if not _valid_ts(core["rotated_at"]):
                raise ValueError("rotated_at must be ISO-8601 UTC, within clock-skew tolerance of now")
            for other_did, other in agents.items():
                if other_did != did and other["public_key"] == core["new_public_jwk"]:
                    raise ValueError(f"new key already belongs to {other_did}")
                if other_did != did and other.get("owner_key") == core["new_public_jwk"]:
                    raise ValueError(f"new key already binds {other_did} as owner")
            if len(signatures) != 1:
                raise ValueError("key.rotated carries exactly one signature")
            try:
                verify(canonical(core), signatures[0], signing_key)
            except BadSignatureError as exc:
                raise ValueError(f"rotation signature does not verify: {exc}") from exc
            append(self.log_path, core | {"signatures": list(signatures)})
            identity["public_key"] = core["new_public_jwk"]
            identity["rotated_at"] = core["rotated_at"]
            identity["version"] += 1
            agents[did] = identity
            self._save_agents(agents)
            return core | {"signatures": list(signatures)}

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
        attester = self.did_for_key(jwk)
        if attester is None:
            raise ValueError(
                "attester key is not registered — register the key first"
            )
        attestation = Attestation(
            id=f"att_{uuid.uuid4().hex[:12]}",
            agent=agent,
            attester=attester,
            type=type_,
            signed_at=_now(),
            payload=payload or {},
        )
        return self.record(sign_attestation(attestation, jwk))

    def record(self, attestation: Attestation) -> Attestation:
        """Verify and commit a pre-signed counterparty attestation.

        Enforces: attester registered and not revoked, subject registered
        and not revoked, signature valid under the attester's registered
        public key, and attestation-id uniqueness (replay protection).
        This is the trust boundary for submitted attestations
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
        existing_ids = {
            record.entry.get("id")
            for record in self._records()
            if record.entry.get("kind", "attestation") == "attestation"
        }
        if attestation.id in existing_ids:
            raise ValueError(f"attestation {attestation.id} is already recorded (replay)")
        verify_attestation(
            attestation, agents[attestation.attester]["public_key"]
        )
        append(self.log_path, attestation.to_dict() | {"kind": "attestation"})
        return attestation

    def attestations_for(self, agent: str | None = None) -> list[Attestation]:
        out = []
        for record in load(self.log_path):
            if record.entry.get("kind", "attestation") != "attestation":
                continue
            if agent is None or record.entry.get("agent") == agent:
                out.append(Attestation.from_dict(record.entry))
        return out

    # -- queries --------------------------------------------------------

    def accusations_for(self, agent: str) -> list[dict]:
        """Dispute views for disputes `agent` opened, for accuser scoring."""
        return [
            self._view_from_slot(slot)
            for slot in self._dispute_index().values()
            if slot.get("opened", {}).get("opened_by") == agent
        ]

    def agents(self) -> list[dict]:
        """All registered identities, oldest first."""
        return sorted(self._load_agents().values(), key=lambda i: i["created_at"])

    def query(self, agent: str) -> dict:
        identity = self._load_agents().get(agent)
        if identity is None:
            raise ValueError(f"unknown agent {agent}")
        false_accusations = sum(
            1
            for d in self.accusations_for(agent)
            if d["outcome"] == "rejected"
        )
        result = score_agent(
            self.attestations_for(agent),
            disputes=self.disputes_for(agent),
            false_accusations=false_accusations,
        )
        result["identity"] = identity
        if identity.get("revoked"):
            result["flags"].append("revoked")
        return result

    # -- structured disputes (v0.4) --------------------------------------

    def _records(self):
        return load(self.log_path)

    def _find_attestation_entry(self, attestation_id: str) -> dict | None:
        for record in self._records():
            if record.entry.get("kind", "attestation") != "attestation":
                continue
            if record.entry.get("id") == attestation_id:
                return record.entry
        return None

    def attestation(self, attestation_id: str) -> dict | None:
        """Public lookup of one committed attestation by id."""
        return self._find_attestation_entry(attestation_id)

    def open_dispute(
        self,
        target: str,
        reason: str,
        key_file: str | Path,
        arbiter: str | None = None,
    ) -> dict:
        """Build, sign, and commit a dispute over a specific attestation."""
        jwk = read_key(key_file)
        core = {
            "kind": "dispute.opened",
            "id": f"dsp_{uuid.uuid4().hex[:12]}",
            "target": target,
            "agent": "",  # filled from the target below
            "opened_by": did_from_jwk(jwk),
            "reason": reason,
            "opened_at": _now(),
            "arbiter": arbiter,
        }
        target_entry = self._find_attestation_entry(target)
        if target_entry is None:
            raise ValueError(f"unknown target attestation {target}")
        core["agent"] = target_entry["agent"]
        signature = sign(canonical(core), jwk)
        return self.commit_open_dispute(core, [signature])

    def commit_open_dispute(self, core: dict, signatures: list[str]) -> dict:
        """Verify and append a pre-signed dispute.opened record (API path)."""
        agents = self._load_agents()
        required = ("kind", "id", "target", "agent", "opened_by", "reason", "opened_at")
        for field in required:
            if field not in core:
                raise ValueError(f"dispute.opened missing field {field}")
        if not core["id"].startswith("dsp_"):
            raise ValueError("dispute ids must start with dsp_")
        target_entry = self._find_attestation_entry(core["target"])
        if target_entry is None:
            raise ValueError(f"unknown target attestation {core['target']}")
        if core["agent"] != target_entry["agent"]:
            raise ValueError("disputed agent does not match the target attestation")
        opener = agents.get(core["opened_by"])
        if opener is None:
            raise ValueError(f"unknown agent {core['opened_by']}")
        if opener["revoked"]:
            raise ValueError(f"opener {core['opened_by']} is revoked")
        if core.get("arbiter"):
            arb = agents.get(core["arbiter"])
            if arb is None:
                raise ValueError(f"unknown arbiter {core['arbiter']}")
            if arb["revoked"]:
                raise ValueError(f"arbiter {core['arbiter']} is revoked")
            if core["arbiter"] == core["agent"]:
                raise ValueError("the disputed agent cannot be its own arbiter")
        if self._dispute_state(core["id"]) is not None:
            raise ValueError(f"dispute {core['id']} already exists")
        if not _valid_ts(core["opened_at"]):
            raise ValueError("opened_at must be ISO-8601 UTC, within clock-skew tolerance of now")
        self._enforce_dispute_rate_limits(core)
        if len(signatures) != 1:
            raise ValueError("dispute.opened carries exactly one signature")
        try:
            verify(canonical(core), signatures[0], opener["public_key"])
        except BadSignatureError as exc:
            raise ValueError(f"opening signature does not verify: {exc}") from exc
        entry = core | {"signatures": list(signatures)}
        append(self.log_path, entry)
        return entry

    def _enforce_dispute_rate_limits(self, core: dict) -> None:
        """Clock-free griefing containment over currently-open disputes."""
        open_disputes = [
            slot["opened"]
            for slot in self._dispute_index().values()
            if slot.get("opened") and slot.get("resolution") is None
        ]
        for opened in open_disputes:
            if opened["opened_by"] == core["opened_by"] and opened["target"] == core["target"]:
                raise ValueError(
                    f"opener already has an open dispute over {core['target']}"
                )
        opener_load = sum(
            1 for o in open_disputes if o["opened_by"] == core["opened_by"]
        )
        if opener_load >= MAX_OPEN_DISPUTES_PER_OPENER:
            raise ValueError(
                f"opener {core['opened_by']} already holds "
                f"{MAX_OPEN_DISPUTES_PER_OPENER} open disputes"
            )
        target_load = sum(1 for o in open_disputes if o["target"] == core["target"])
        if target_load >= MAX_OPEN_DISPUTES_PER_TARGET:
            raise ValueError(
                f"attestation {core['target']} already has "
                f"{MAX_OPEN_DISPUTES_PER_TARGET} open disputes"
            )

    def resolve_dispute(
        self, dispute: str, outcome: str, key_files: list[str | Path]
    ) -> dict:
        """Build, sign, and commit a resolution.

        Mutual mode: signatures from BOTH the opener and the disputed agent.
        Arbiter mode (arbiter set at opening): the arbiter's signature alone.
        """
        state = self._dispute_state(dispute)
        if state is None:
            raise ValueError(f"unknown dispute {dispute}")
        if state["resolution"] is not None:
            raise ValueError(f"dispute {dispute} is already resolved")
        if outcome not in DISPUTE_OUTCOMES:
            raise ValueError(f"outcome must be one of {sorted(DISPUTE_OUTCOMES)}")
        signers = [did_from_jwk(read_key(k)) for k in key_files]
        core = {
            "kind": "dispute.resolved",
            "dispute": dispute,
            "outcome": outcome,
            "resolved_by": signers,
            "resolved_at": _now(),
        }
        signatures = [
            sign(canonical(core), read_key(k)) for k in key_files
        ]
        return self.commit_resolution(core, signatures)

    def commit_resolution(self, core: dict, signatures: list[str]) -> dict:
        """Verify and append a pre-signed dispute.resolved record (API path)."""
        agents = self._load_agents()
        state = self._dispute_state(core.get("dispute", ""))
        if state is None:
            raise ValueError(f"unknown dispute {core.get('dispute')}")
        if state["resolution"] is not None:
            raise ValueError(f"dispute {core['dispute']} is already resolved")
        if core.get("outcome") not in DISPUTE_OUTCOMES:
            raise ValueError(f"outcome must be one of {sorted(DISPUTE_OUTCOMES)}")
        if not _valid_ts(core.get("resolved_at")):
            raise ValueError("resolved_at must be present, ISO-8601 UTC, within clock-skew tolerance of now")
        resolved_by = core.get("resolved_by", [])
        if not resolved_by or len(signatures) != len(resolved_by):
            raise ValueError("resolved_by and signatures must be non-empty and paired 1:1")
        identities = []
        for did in resolved_by:
            identity = agents.get(did)
            if identity is None:
                raise ValueError(f"unknown agent {did}")
            if identity["revoked"]:
                raise ValueError(f"resolver {did} is revoked")
            identities.append(identity)
        opened = state["opened"]
        if opened.get("arbiter"):
            if opened["arbiter"] not in resolved_by:
                raise ValueError(
                    f"arbiter {opened['arbiter']} must sign the resolution"
                )
        else:  # mutual mode
            needed = {opened["opened_by"], opened["agent"]}
            if not needed.issubset(set(resolved_by)):
                raise ValueError(
                    f"mutual resolution requires signatures from {sorted(needed)}"
                )
        for signature, identity in zip(signatures, identities):
            try:
                verify(canonical(core), signature, identity["public_key"])
            except BadSignatureError as exc:
                raise ValueError(f"resolution signature does not verify: {exc}") from exc
        entry = core | {"signatures": list(signatures)}
        append(self.log_path, entry)
        return entry

    def _dispute_index(self) -> dict[str, dict]:
        """One pass over the log: {dispute_id: {"opened": entry, "resolution": entry|None}}."""
        index: dict[str, dict] = {}
        for record in self._records():
            entry = record.entry
            kind = entry.get("kind")
            if kind == "dispute.opened":
                index.setdefault(entry["id"], {})["opened"] = entry
            elif kind == "dispute.resolved":
                index.setdefault(entry["dispute"], {})["resolution"] = entry
        return index

    def _dispute_state(self, dispute_id: str) -> dict | None:
        slot = self._dispute_index().get(dispute_id, {})
        opened = slot.get("opened")
        if opened is None:
            return None
        resolution = slot.get("resolution")
        return {
            "opened": opened,
            "resolution": resolution,
            "status": "resolved" if resolution else "open",
            "outcome": resolution["outcome"] if resolution else None,
        }

    def _view_from_slot(self, slot: dict) -> dict:
        opened, resolution = slot["opened"], slot.get("resolution")
        view = {k: opened[k] for k in ("id", "target", "agent", "opened_by", "reason", "opened_at")}
        view["arbiter"] = opened.get("arbiter")
        view["status"] = "resolved" if resolution else "open"
        view["outcome"] = resolution["outcome"] if resolution else None
        if resolution:
            view["resolved_by"] = resolution["resolved_by"]
            view["resolved_at"] = resolution["resolved_at"]
        return view

    def dispute_view(self, dispute_id: str) -> dict:
        slot = self._dispute_index().get(dispute_id)
        if not slot or "opened" not in slot:
            raise ValueError(f"unknown dispute {dispute_id}")
        return self._view_from_slot(slot)

    def disputes_for(self, agent: str | None = None) -> list[dict]:
        """Dispute views; for one disputed party when `agent` is given,
        all disputes otherwise. Status and outcome for fault assignment."""
        return [
            self._view_from_slot(slot)
            for slot in self._dispute_index().values()
            if "opened" in slot and (agent is None or slot["opened"].get("agent") == agent)
        ]

    def all_disputes(self) -> list[dict]:
        return [
            self._view_from_slot(slot)
            for slot in self._dispute_index().values()
            if "opened" in slot
        ]

    # -- deals & settlement (v0.6) ---------------------------------------

    def _deal_index(self) -> dict[str, dict]:
        """One pass over the log: {deal_id: {opened, settled, cancelled}}."""
        index: dict[str, dict] = {}
        for record in self._records():
            entry = record.entry
            kind = entry.get("kind")
            if kind == "deal.opened":
                index.setdefault(entry["id"], {})["opened"] = entry
            elif kind == "deal.settled":
                index.setdefault(entry["deal"], {})["settled"] = entry
            elif kind == "deal.cancelled":
                index.setdefault(entry["deal"], {})["cancelled"] = entry
        return index

    def _deal_state(self, deal_id: str) -> dict | None:
        slot = self._deal_index().get(deal_id, {})
        if "opened" not in slot:
            return None
        return {
            "opened": slot["opened"],
            "settled": slot.get("settled"),
            "cancelled": slot.get("cancelled"),
        }

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
        """Build, sign (both parties), and commit a deal."""
        payer_jwk = read_key(payer_key_file)
        payee_jwk = read_key(payee_key_file)
        payee_did = self.did_for_key(payee_jwk)
        if payee is not None and payee != payee_did:
            raise ValueError(f"payee key belongs to {payee_did}, not {payee}")
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
        signatures = [
            sign(canonical(core), payer_jwk),
            sign(canonical(core), payee_jwk),
        ]
        return self.commit_deal_open(core, signatures)

    def commit_deal_open(self, core: dict, signatures: list[str]) -> dict:
        """Verify and append a mutually-signed deal (API path)."""
        agents = self._load_agents()
        if core.get("kind") != "deal.opened":
            raise ValueError("expected a deal.opened record")
        for field in ("id", "payer", "payee", "amount_usd", "condition_type", "opened_at"):
            if field not in core:
                raise ValueError(f"deal.opened missing field {field}")
        if not core["id"].startswith("deal_"):
            raise ValueError("deal ids must start with deal_")
        if core["payer"] == core["payee"]:
            raise ValueError("payer and payee must differ")
        for role in ("payer", "payee"):
            identity = agents.get(core[role])
            if identity is None:
                raise ValueError(f"unknown {role} {core[role]}")
            if identity["revoked"]:
                raise ValueError(f"{role} {core[role]} is revoked")
        if not isinstance(core["amount_usd"], (int, float)) or core["amount_usd"] < 0:
            raise ValueError("amount_usd must be a non-negative number")
        if core["condition_type"] not in DEAL_CONDITION_TYPES:
            raise ValueError(f"condition_type must be one of {sorted(DEAL_CONDITION_TYPES)}")
        if not _valid_ts(core["opened_at"]):
            raise ValueError("opened_at must be ISO-8601 UTC, within clock-skew tolerance of now")
        if core.get("deadline") is not None:
            try:
                deadline_dt = datetime.fromisoformat(str(core["deadline"]).replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError("deadline must be ISO-8601") from exc
            if deadline_dt <= datetime.fromisoformat(core["opened_at"].replace("Z", "+00:00")):
                raise ValueError("deadline must be after opened_at")
        if core.get("arbiter"):
            arb = agents.get(core["arbiter"])
            if arb is None:
                raise ValueError(f"unknown arbiter {core['arbiter']}")
            if arb["revoked"]:
                raise ValueError(f"arbiter {core['arbiter']} is revoked")
            if core["arbiter"] in (core["payer"], core["payee"]):
                raise ValueError("the arbiter cannot be a party to the deal")
        if self._deal_state(core["id"]) is not None:
            raise ValueError(f"deal {core['id']} already exists")
        if len(signatures) != 2:
            raise ValueError("deal.opened carries exactly two signatures (payer, payee)")
        for who, signature in zip((core["payer"], core["payee"]), signatures):
            try:
                verify(canonical(core), signature, agents[who]["public_key"])
            except BadSignatureError as exc:
                raise ValueError(f"signature for {who} does not verify: {exc}") from exc
        entry = core | {"signatures": list(signatures)}
        append(self.log_path, entry)
        return entry

    def settle_deal(self, deal: str, settlement: str, key_file: str | Path) -> dict:
        """Build, sign, and commit a settlement citing a condition attestation."""
        jwk = read_key(key_file)
        settled_by = self.did_for_key(jwk)
        core = {
            "kind": "deal.settled",
            "deal": deal,
            "settlement": settlement,
            "settled_by": settled_by,
            "settled_at": _now(),
        }
        signature = sign(canonical(core), jwk)
        return self.commit_deal_settle(core, [signature])

    def commit_deal_settle(self, core: dict, signatures: list[str]) -> dict:
        """Verify and append a settlement (API path).

        Escrow semantics, rail-agnostically: settlement only commits when a
        real, signed condition attestation exists on the chain, bound to
        this deal via payload.deal, of the agreed type, about the payee,
        signed by the payer (or the deal's arbiter) after the deal opened
        and (for payer settlement) before the deadline.
        """
        agents = self._load_agents()
        if core.get("kind") != "deal.settled":
            raise ValueError("expected a deal.settled record")
        for field in ("deal", "settlement", "settled_by", "settled_at"):
            if field not in core:
                raise ValueError(f"deal.settled missing field {field}")
        if not _valid_ts(core["settled_at"]):
            raise ValueError("settled_at must be ISO-8601 UTC, within clock-skew tolerance of now")
        state = self._deal_state(core["deal"])
        if state is None:
            raise ValueError(f"unknown deal {core['deal']}")
        if state["settled"] is not None:
            raise ValueError(f"deal {core['deal']} is already settled")
        if state["cancelled"] is not None:
            raise ValueError(f"deal {core['deal']} is cancelled")
        deal = state["opened"]
        allowed_signers = {deal["payer"]}
        if deal.get("arbiter"):
            allowed_signers.add(deal["arbiter"])
        if core["settled_by"] not in allowed_signers:
            raise ValueError("settlement must be signed by the payer or the deal arbiter")
        signer = agents.get(core["settled_by"])
        if signer is None:
            raise ValueError(f"unknown agent {core['settled_by']}")
        if signer["revoked"]:
            raise ValueError(f"settler {core['settled_by']} is revoked")

        att = self._find_attestation_entry(core["settlement"])
        if att is None:
            raise ValueError(f"settlement attestation {core['settlement']} not found on chain")
        if att.get("agent") != deal["payee"]:
            raise ValueError("condition attestation is not about the payee")
        if att.get("type") != deal["condition_type"]:
            raise ValueError(
                f"condition attestation type {att.get('type')!r} != agreed {deal['condition_type']!r}"
            )
        if att.get("attester") not in allowed_signers:
            raise ValueError("condition attestation must be signed by the payer or the arbiter")
        if att.get("payload", {}).get("deal") != core["deal"]:
            raise ValueError("condition attestation is not bound to this deal (payload.deal)")
        att_signed = datetime.fromisoformat(att["signed_at"].replace("Z", "+00:00"))
        opened_at = datetime.fromisoformat(deal["opened_at"].replace("Z", "+00:00"))
        if att_signed < opened_at:
            raise ValueError("condition attestation predates the deal")
        if deal.get("deadline"):
            # the registry clock decides, never the client's settled_at —
            # a backdated settlement must not resurrect an expired deal
            deadline_dt = datetime.fromisoformat(str(deal["deadline"]).replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > deadline_dt and core["settled_by"] != deal.get("arbiter"):
                raise ValueError("deadline passed: only the arbiter may settle now")

        if len(signatures) != 1:
            raise ValueError("deal.settled carries exactly one signature")
        try:
            verify(canonical(core), signatures[0], signer["public_key"])
        except BadSignatureError as exc:
            raise ValueError(f"settlement signature does not verify: {exc}") from exc
        entry = core | {"signatures": list(signatures)}
        append(self.log_path, entry)
        return entry

    def cancel_deal(
        self, deal: str, payer_key_file: str | Path, payee_key_file: str | Path, reason: str = ""
    ) -> dict:
        """Mutual cancellation (the refund path) — no fault assigned."""
        state = self._deal_state(deal)
        if state is None:
            raise ValueError(f"unknown deal {deal}")
        payer_jwk = read_key(payer_key_file)
        core = {
            "kind": "deal.cancelled",
            "deal": deal,
            "reason": reason,
            "cancelled_at": _now(),
        }
        signatures = [
            sign(canonical(core), payer_jwk),
            sign(canonical(core), read_key(payee_key_file)),
        ]
        return self.commit_deal_cancel(core, signatures)

    def commit_deal_cancel(self, core: dict, signatures: list[str]) -> dict:
        agents = self._load_agents()
        if core.get("kind") != "deal.cancelled":
            raise ValueError("expected a deal.cancelled record")
        for field in ("deal", "cancelled_at"):
            if field not in core:
                raise ValueError(f"deal.cancelled missing field {field}")
        if not _valid_ts(core["cancelled_at"]):
            raise ValueError("cancelled_at must be ISO-8601 UTC, within clock-skew tolerance of now")
        state = self._deal_state(core["deal"])
        if state is None:
            raise ValueError(f"unknown deal {core['deal']}")
        if state["settled"] is not None:
            raise ValueError(f"deal {core['deal']} is already settled")
        if state["cancelled"] is not None:
            raise ValueError(f"deal {core['deal']} is already cancelled")
        deal = state["opened"]
        if len(signatures) != 2:
            raise ValueError("deal.cancelled carries exactly two signatures (payer, payee)")
        for who, signature in zip((deal["payer"], deal["payee"]), signatures):
            identity = agents.get(who)
            if identity is None:
                raise ValueError(f"unknown agent {who}")
            if identity["revoked"]:
                raise ValueError(f"{who} is revoked")
            try:
                verify(canonical(core), signature, identity["public_key"])
            except BadSignatureError as exc:
                raise ValueError(f"signature for {who} does not verify: {exc}") from exc
        entry = core | {"signatures": list(signatures)}
        append(self.log_path, entry)
        return entry

    def _contested_targets(self) -> set[str]:
        """Attestation ids whose disputes were UPHELD — their evidence was
        overturned in court, so any deal settled on them is contested."""
        contested = set()
        for slot in self._dispute_index().values():
            opened = slot.get("opened")
            resolution = slot.get("resolution") or {}
            if opened and resolution.get("outcome") == "upheld":
                contested.add(opened["target"])
        return contested

    def _deal_view_from_slot(self, slot: dict, contested_targets: set[str] | None = None) -> dict:
        opened = slot["opened"]
        view = {
            k: opened[k] for k in
            ("id", "payer", "payee", "amount_usd", "terms", "condition_type", "opened_at")
        }
        view["deadline"] = opened.get("deadline")
        view["arbiter"] = opened.get("arbiter")
        if slot.get("settled") is not None:
            view["status"] = "settled"
            view["settlement"] = slot["settled"]["settlement"]
            view["settled_at"] = slot["settled"]["settled_at"]
            if contested_targets is None:
                contested_targets = self._contested_targets()
            if view["settlement"] in contested_targets:
                # the chain is immutable — the record stands, but consumers
                # are warned its evidence was overturned in court (§10/§11)
                view["contested"] = True
        elif slot.get("cancelled") is not None:
            view["status"] = "cancelled"
        else:
            view["status"] = "open"
            if opened.get("deadline"):
                deadline_dt = datetime.fromisoformat(str(opened["deadline"]).replace("Z", "+00:00"))
                if deadline_dt < datetime.now(timezone.utc):
                    view["status"] = "expired"  # registry runs no timers; expiry is derived
        return view

    def deal_view(self, deal_id: str) -> dict:
        slot = self._deal_index().get(deal_id)
        if not slot or "opened" not in slot:
            raise ValueError(f"unknown deal {deal_id}")
        return self._deal_view_from_slot(slot)

    def deals_for(self, agent: str | None = None) -> list[dict]:
        contested_targets = self._contested_targets()  # one pass, not one per deal
        views = []
        for slot in self._deal_index().values():
            if "opened" not in slot:
                continue
            view = self._deal_view_from_slot(slot, contested_targets)
            if agent is None or agent in (view["payer"], view["payee"]):
                views.append(view)
        return views

    def evidence_bundle(self, dispute_id: str) -> dict:
        """Portable, self-verifying court document for one dispute.

        Contains the signed records (opening, resolution, target
        attestation) plus the public identities needed to verify every
        signature offline. Subset bundles prove record integrity and
        authenticity; proving *chain membership* requires the full log —
        `meta.head` lets any live registry attest to it later.
        """
        slot = self._dispute_index().get(dispute_id)
        if not slot or "opened" not in slot:
            raise ValueError(f"unknown dispute {dispute_id}")
        target_id = slot["opened"]["target"]
        records = self._records()
        wanted: set[str] = {dispute_id}
        subset = []
        for record in records:
            entry = record.entry
            if entry.get("kind") == "dispute.opened" and entry.get("id") in wanted:
                subset.append(record)
            elif entry.get("kind") == "dispute.resolved" and entry.get("dispute") in wanted:
                subset.append(record)
            elif (
                entry.get("kind", "attestation") == "attestation"
                and entry.get("id") == target_id
            ):
                subset.append(record)
        agents = self._load_agents()
        involved: set[str] = set()
        for record in subset:
            entry = record.entry
            kind = entry.get("kind", "attestation")
            if kind == "attestation":
                involved.update((entry["agent"], entry["attester"]))
            elif kind == "dispute.opened":
                involved.add(entry["opened_by"])
                if entry.get("arbiter"):
                    involved.add(entry["arbiter"])
            elif kind == "dispute.resolved":
                involved.update(entry["resolved_by"])
        identities = {
            did: {"public_key": agents[did]["public_key"], "revoked": agents[did]["revoked"]}
            for did in involved
            if did in agents
        }
        return {
            "format": "agentcred/evidence-bundle@1",
            "dispute": dispute_id,
            "records": [
                {"index": r.index, "prev": r.prev, "entry": r.entry, "hash": r.hash}
                for r in subset
            ],
            "identities": identities,
            "meta": {
                "log_length": len(records),
                "head": records[-1].hash if records else "0" * 64,
            },
            "note": (
                "subset bundle: record integrity and signatures are provable "
                "offline; chain membership requires the full log (meta.head "
                "anchors against a live registry)"
            ),
        }

    def head(self) -> dict:
        """Chain head anchor: last record hash + record count.

        A hash chain proves its records are unmodified, but a truncated
        chain is internally consistent — completeness can only be proven
        against an anchor published OUTSIDE the log file. Record this
        somewhere the log cannot rewrite (another system, a printed
        checkpoint, a commit) and verify against it.
        """
        records = self._records()
        return {
            "head": records[-1].hash if records else "0" * 64,
            "length": len(records),
        }

    def verify(
        self,
        expected_head: str | None = None,
        expected_length: int | None = None,
    ) -> dict:
        """Walk the log: chain integrity + every signature against the
        registered attester key, optionally against external head/length
        anchors (truncation detection). `ok` is False on any problem."""
        problems: list[dict] = []
        chain = "ok"
        records = []
        try:
            records = load(self.log_path)
            verify_chain(records)
        except LogTamperError as exc:
            chain = f"broken at record {exc.index}: {exc.reason}"
            problems.append({"index": exc.index, "issue": "chain", "detail": str(exc)})

        anchors = self.head()
        if expected_head is not None and expected_head != anchors["head"]:
            problems.append(
                {"issue": "head_anchor_mismatch",
                 "detail": f"expected {expected_head}, chain head is {anchors['head']} — history was truncated or rewound"}
            )
        if expected_length is not None and expected_length != anchors["length"]:
            problems.append(
                {"issue": "length_anchor_mismatch",
                 "detail": f"expected {expected_length} records, found {anchors['length']}"}
            )

        agents = self._load_agents()
        valid = 0
        opened_seen: set[str] = set()
        attestation_ids_seen: set[str] = set()

        # Key timeline: which public key was valid for each agent at each
        # chain position. Rotation records carry the old key precisely so
        # that ALL history stays verifiable after a key change — an
        # attestation signed by a pre-rotation key must check against the
        # pre-rotation key, not the current one.
        rotation_timeline: dict[str, list[tuple[int, dict, dict]]] = {}
        for record in records:
            if record.entry.get("kind") == "key.rotated":
                entry = record.entry
                rotation_timeline.setdefault(entry["agent"], []).append(
                    (record.index, entry["old_public_jwk"], entry["new_public_jwk"])
                )

        def key_for(who: str, index: int) -> dict | None:
            events = rotation_timeline.get(who, [])
            if not events:
                return agents.get(who, {}).get("public_key")
            key = events[0][1]  # original key: the first rotation's old key
            for event_index, _old, new_key in events:
                if event_index < index:
                    key = new_key
            return key

        def _check_sig(index: int, who: str, message: bytes, signature: str) -> bool:
            if who not in agents:
                problems.append({"index": index, "issue": "unknown_agent", "detail": who})
                return False
            jwk = key_for(who, index)
            if not jwk:
                problems.append({"index": index, "issue": "unknown_attester", "detail": who})
                return False
            try:
                verify(message, signature, jwk)
                return True
            except (BadSignatureError, ValueError) as exc:
                problems.append(
                    {"index": index, "issue": "bad_signature", "detail": f"{who}: {exc}"}
                )
                return False

        for record in records:
            entry = record.entry
            kind = entry.get("kind", "attestation")
            if kind == "attestation":
                attestation_ids_seen.add(entry.get("id"))
                att = Attestation.from_dict(entry)
                if att.agent not in agents:
                    problems.append(
                        {"index": record.index, "issue": "unknown_agent", "detail": att.agent}
                    )
                    continue
                jwk = key_for(att.attester, record.index)
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
            elif kind == "dispute.opened":
                core = {k: v for k, v in entry.items() if k != "signatures"}
                if _check_sig(record.index, entry["opened_by"], canonical(core), entry["signatures"][0]):
                    valid += 1
                opened_seen.add(entry["id"])
            elif kind == "dispute.resolved":
                if entry.get("dispute") not in opened_seen:
                    problems.append(
                        {"index": record.index, "issue": "resolution_without_dispute",
                         "detail": entry.get("dispute")}
                    )
                    continue
                core = {k: v for k, v in entry.items() if k != "signatures"}
                for who, signature in zip(entry.get("resolved_by", []), entry.get("signatures", [])):
                    if _check_sig(record.index, who, canonical(core), signature):
                        valid += 1
            elif kind == "agent.revoked":
                core = {k: v for k, v in entry.items() if k != "signatures"}
                if entry.get("agent") not in agents:
                    problems.append(
                        {"index": record.index, "issue": "unknown_agent", "detail": entry.get("agent")}
                    )
                    continue
                if entry.get("authority") == "owner":
                    signing_key = entry.get("authority_public_jwk")
                else:
                    signing_key = key_for(entry["agent"], record.index)
                if not signing_key:
                    problems.append(
                        {"index": record.index, "issue": "unknown_attester", "detail": entry.get("agent")}
                    )
                    continue
                try:
                    verify(canonical(core), entry["signatures"][0], signing_key)
                    valid += 1
                except (BadSignatureError, ValueError, KeyError) as exc:
                    problems.append(
                        {"index": record.index, "issue": "bad_signature", "detail": str(exc)}
                    )
            elif kind == "owner.bound":
                core = {k: v for k, v in entry.items() if k != "signatures"}
                if entry.get("agent") not in agents:
                    problems.append(
                        {"index": record.index, "issue": "unknown_agent", "detail": entry.get("agent")}
                    )
                    continue
                # self-contained: owner consent proven against the owner key
                # the record itself carries
                try:
                    verify(canonical(core), entry["signatures"][0], entry["owner_public_jwk"])
                    valid += 1
                except (BadSignatureError, ValueError, KeyError) as exc:
                    problems.append(
                        {"index": record.index, "issue": "bad_signature", "detail": str(exc)}
                    )
            elif kind == "key.rotated":
                core = {k: v for k, v in entry.items() if k != "signatures"}
                if entry.get("agent") not in agents:
                    problems.append(
                        {"index": record.index, "issue": "unknown_agent", "detail": entry.get("agent")}
                    )
                    continue
                # self-contained: 'self' rotations verify against the old agent
                # key the record carries; owner rotations against the owner key
                signing_key = (
                    entry.get("authority_public_jwk")
                    if entry.get("authority") == "owner"
                    else entry["old_public_jwk"]
                )
                try:
                    verify(canonical(core), entry["signatures"][0], signing_key)
                    valid += 1
                except (BadSignatureError, ValueError, KeyError) as exc:
                    problems.append(
                        {"index": record.index, "issue": "bad_signature", "detail": str(exc)}
                    )
            elif kind == "deal.opened":
                core = {k: v for k, v in entry.items() if k != "signatures"}
                for who, signature in zip(
                    (entry.get("payer"), entry.get("payee")), entry.get("signatures", [])
                ):
                    if _check_sig(record.index, who, canonical(core), signature):
                        valid += 1
            elif kind == "deal.settled":
                core = {k: v for k, v in entry.items() if k != "signatures"}
                if entry.get("settlement") not in attestation_ids_seen:
                    problems.append(
                        {"index": record.index, "issue": "settlement_missing",
                         "detail": entry.get("settlement")}
                    )
                    continue
                if _check_sig(
                    record.index, entry.get("settled_by"), canonical(core),
                    (entry.get("signatures") or [None])[0],
                ):
                    valid += 1
            elif kind == "deal.cancelled":
                core = {k: v for k, v in entry.items() if k != "signatures"}
                state = self._deal_index().get(entry.get("deal"), {})
                parties = (
                    state.get("opened", {}).get("payer"),
                    state.get("opened", {}).get("payee"),
                )
                for who, signature in zip(parties, entry.get("signatures", [])):
                    if _check_sig(record.index, who, canonical(core), signature):
                        valid += 1
            else:
                problems.append(
                    {"index": record.index, "issue": "unknown_kind", "detail": kind}
                )
        return {
            "ok": not problems,
            "chain": chain,
            "records": len(records),
            "signatures_valid": valid,
            "problems": problems,
        }
