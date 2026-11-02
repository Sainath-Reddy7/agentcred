"""Offline verification of evidence bundles (v0.4).

An evidence bundle is the portable court document of the AgentCred dispute
system: the signed records for one dispute plus the public identities
needed to check every signature without any registry connection. See
spec §10.
"""

from __future__ import annotations

from typing import Any

from nacl.exceptions import BadSignatureError

from .canonical import canonical
from .crypto import verify
from .log import LogRecord, record_hash
from .models import Attestation

BUNDLE_FORMAT = "agentcred/evidence-bundle@1"


def _core(entry: dict) -> dict:
    """The fields covered by a dispute record's signatures."""
    return {k: v for k, v in entry.items() if k != "signatures"}


def verify_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    """Verify an evidence bundle offline. Returns a report.

    Checks: format marker, per-record hash recomputation, internal
    references (resolution -> dispute -> target attestation), and every
    signature against the identities carried in the bundle. Chain
    membership of the subset is explicitly *not* claimed (see the bundle's
    own note) — `meta.head` anchors it against a live registry instead.
    """
    problems: list[dict] = []

    if bundle.get("format") != BUNDLE_FORMAT:
        return {
            "ok": False,
            "records": 0,
            "signatures_valid": 0,
            "membership_proven": False,
            "problems": [{"issue": "bad_format", "detail": bundle.get("format")}],
        }

    identities = bundle.get("identities", {})
    records: list[LogRecord] = []
    for raw in bundle.get("records", []):
        try:
            record = LogRecord(
                index=raw["index"], prev=raw["prev"], entry=raw["entry"], hash=raw["hash"]
            )
        except (KeyError, TypeError) as exc:
            problems.append({"issue": "malformed_record", "detail": str(exc)})
            continue
        if record.hash != record_hash(record.index, record.prev, record.entry):
            problems.append({"index": record.index, "issue": "record_hash_mismatch"})
            continue
        records.append(record)

    def check_sig(index: int, who: str, message: bytes, signature: str | None) -> bool:
        if not signature:
            problems.append({"index": index, "issue": "unsigned", "detail": who})
            return False
        identity = identities.get(who)
        if not identity:
            problems.append({"index": index, "issue": "missing_identity", "detail": who})
            return False
        try:
            verify(message, signature, identity["public_key"])
            return True
        except (BadSignatureError, ValueError) as exc:
            problems.append(
                {"index": index, "issue": "bad_signature", "detail": f"{who}: {exc}"}
            )
            return False

    signatures_valid = 0
    opened: dict[str, dict] = {}
    resolution: dict | None = None
    target: dict | None = None

    for record in records:
        entry = record.entry
        kind = entry.get("kind", "attestation")
        if kind == "dispute.opened":
            signature = (entry.get("signatures") or [None])[0]
            if check_sig(record.index, entry["opened_by"], canonical(_core(entry)), signature):
                signatures_valid += 1
            opened[entry["id"]] = entry
        elif kind == "dispute.resolved":
            if entry.get("dispute") not in opened:
                problems.append(
                    {"index": record.index, "issue": "resolution_without_dispute"}
                )
                continue
            core = canonical(_core(entry))
            for who, signature in zip(
                entry.get("resolved_by", []), entry.get("signatures", [])
            ):
                if check_sig(record.index, who, core, signature):
                    signatures_valid += 1
            resolution = entry
        elif kind == "attestation":
            att = Attestation.from_dict(entry)
            if check_sig(
                record.index, att.attester, canonical(att.unsigned_dict()), att.signature
            ):
                signatures_valid += 1
            target = entry
        else:
            problems.append({"index": record.index, "issue": "unknown_kind", "detail": kind})

    dispute_id = bundle.get("dispute")
    if dispute_id not in opened:
        problems.append({"issue": "dispute_record_missing", "detail": dispute_id})
    if resolution is None:
        problems.append({"issue": "no_resolution", "detail": "bundle contains an open dispute"})
    if dispute_id in opened:
        expected_target = opened[dispute_id].get("target")
        if target is None or target.get("id") != expected_target:
            # the bundle must carry the exact attestation the dispute names —
            # otherwise a swapped-in record misattributes the whole document
            problems.append(
                {"issue": "target_mismatch",
                 "detail": f"dispute targets {expected_target}, bundle carries {target.get('id') if target else None}"}
            )

    return {
        "ok": not problems,
        "records": len(records),
        "signatures_valid": signatures_valid,
        "membership_proven": False,
        "problems": problems,
        "note": bundle.get("note", ""),
    }
