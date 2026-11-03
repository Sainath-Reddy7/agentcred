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
from .log import LogTamperError, append, load, verify_chain
from .models import Attestation
from .scoring import score_agent

DISPUTE_OUTCOMES = frozenset({"upheld", "rejected", "settled"})
# Griefing containment (spec §10): while open, disputes count provisionally
# against the accused — so mass-opening must not be free.
MAX_OPEN_DISPUTES_PER_OPENER = 5
MAX_OPEN_DISPUTES_PER_TARGET = 3


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

    def disputes_for(self, agent: str) -> list[dict]:
        """Dispute views for scoring: every dispute where `agent` is the
        disputed party, with status and outcome for fault assignment."""
        return [
            self._view_from_slot(slot)
            for slot in self._dispute_index().values()
            if slot.get("opened", {}).get("agent") == agent
        ]

    def all_disputes(self) -> list[dict]:
        return [
            self._view_from_slot(slot)
            for slot in self._dispute_index().values()
            if "opened" in slot
        ]

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
        opened_seen: set[str] = set()

        def _check_sig(index: int, who: str, message: bytes, signature: str) -> bool:
            identity = agents.get(who)
            if identity is None:
                problems.append({"index": index, "issue": "unknown_agent", "detail": who})
                return False
            try:
                verify(message, signature, identity["public_key"])
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
                att = Attestation.from_dict(entry)
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
