"""Full-registry export & verification (v0.8.2).

An export bundles the complete registry state — identities plus the full
hash-chained log plus the head anchor — so a registry can be backed up,
migrated, or restored elsewhere. Verification is end-to-end:

1. the chain re-verifies (record hashes, links, ordering);
2. the anchor matches (truncation detection, §8);
3. identity state is cross-checked against the chain: owner bindings,
   rotation timelines, and revocations must agree — v0.8.1's
   chain-recorded revocation is what makes an *un-revocation* tamper
   detectable;
4. every record's referenced identity must exist.

Honest limit: an identity that never rotated, never bound an owner, and
has no history is anchored only by agents.json — its key is
export-trusted (documented in spec §9).
"""

from __future__ import annotations

from typing import Any

from .log import GENESIS, LogRecord, verify_chain

EXPORT_FORMAT = "agentcred/registry-export@1"


def export_state(identities: dict, records: list[LogRecord]) -> dict:
    return {
        "format": EXPORT_FORMAT,
        "identities": identities,
        "records": [
            {"index": r.index, "prev": r.prev, "entry": r.entry, "hash": r.hash}
            for r in records
        ],
        "anchor": {
            "head": records[-1].hash if records else GENESIS,
            "length": len(records),
        },
    }


def _record_parties(entry: dict) -> tuple[str, ...]:
    kind = entry.get("kind", "attestation")
    if kind == "attestation":
        return entry.get("agent"), entry.get("attester")
    if kind == "dispute.opened":
        return entry.get("agent"), entry.get("opened_by"), entry.get("arbiter")
    if kind == "dispute.resolved":
        return tuple(entry.get("resolved_by", []))
    if kind in ("key.rotated", "agent.revoked", "owner.bound"):
        return (entry.get("agent"),)
    if kind == "deal.opened":
        return entry.get("payer"), entry.get("payee"), entry.get("arbiter")
    if kind == "deal.settled":
        return (entry.get("settled_by"),)
    if kind == "deal.cancelled":
        return ()  # parties are resolved via the deal record itself
    return ()


def verify_export_state(bundle: dict[str, Any]) -> dict[str, Any]:
    """Verify a registry export end-to-end. Returns a report."""
    problems: list[dict] = []

    if bundle.get("format") != EXPORT_FORMAT:
        return {"ok": False, "problems": [{"issue": "bad_format"}]}

    identities = bundle.get("identities") or {}
    records: list[LogRecord] = []
    for raw in bundle.get("records", []):
        try:
            records.append(
                LogRecord(
                    index=raw["index"], prev=raw["prev"],
                    entry=raw["entry"], hash=raw["hash"],
                )
            )
        except (KeyError, TypeError) as exc:
            problems.append({"issue": "malformed_record", "detail": str(exc)})

    # 1. chain
    try:
        verify_chain(records)
    except Exception as exc:  # LogTamperError or its message shape
        problems.append({"issue": "chain", "detail": str(exc)})

    # 2. anchor
    anchor = bundle.get("anchor") or {}
    actual_head = records[-1].hash if records else GENESIS
    if anchor.get("head") != actual_head:
        problems.append(
            {"issue": "anchor_mismatch",
             "detail": f"bundle claims head {anchor.get('head')}, records end at {actual_head}"}
        )
    if anchor.get("length") != len(records):
        problems.append(
            {"issue": "anchor_mismatch",
             "detail": f"bundle claims {anchor.get('length')} records, carries {len(records)}"}
        )

    # 3. identity ↔ chain cross-checks (single pass)
    bound: dict[str, dict] = {}
    rotated_to: dict[str, dict] = {}
    revoked_on_chain: set[str] = set()
    for record in records:
        entry = record.entry
        kind = entry.get("kind")
        if kind == "owner.bound":
            bound[entry["agent"]] = entry
        elif kind == "key.rotated":
            rotated_to[entry["agent"]] = entry["new_public_jwk"]
        elif kind == "agent.revoked":
            revoked_on_chain.add(entry["agent"])

    for did, identity in identities.items():
        binding = bound.get(did)
        if binding is not None:
            if identity.get("owner_key") != binding.get("owner_public_jwk"):
                problems.append({"issue": "owner_tampered", "detail": did})
            if identity.get("owner") != binding.get("owner"):
                problems.append({"issue": "owner_tampered", "detail": did})
        elif identity.get("owner_key") is not None or identity.get("owner") != did:
            problems.append({"issue": "owner_unanchored", "detail": did})
        if did in rotated_to and identity.get("public_key") != rotated_to[did]:
            problems.append({"issue": "key_tampered", "detail": did})
        if bool(identity.get("revoked")) != (did in revoked_on_chain):
            problems.append(
                {"issue": "revocation_state_divergence", "detail": did}
            )

    # 4. referenced identities must exist
    known = set(identities)
    for record in records:
        for party in _record_parties(record.entry):
            if party is not None and party not in known:
                problems.append(
                    {"issue": "unknown_identity", "detail": f"record {record.index}: {party}"}
                )

    return {
        "ok": not problems,
        "records": len(records),
        "identities": len(identities),
        "problems": problems,
    }
