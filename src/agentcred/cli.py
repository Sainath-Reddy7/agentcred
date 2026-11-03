"""The `agentcred` command-line interface (v0.2).

    agentcred keygen  --out keys/bot.json
    agentcred register --key keys/bot.json --name invoice-bot --caps invoices.parse
    agentcred attest   --key keys/buyer.json --agent did:agentcred:xxx \
                       --type payment_settled --payload '{"value_usd": 120}'
    agentcred query   --agent did:agentcred:xxx
    agentcred verify
    agentcred log [--agent did:agentcred:xxx]

State lives in --state (default ./agentcred-state): agents.json + log.jsonl.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .crypto import did_from_jwk, generate_keypair, read_key, write_key
from .models import ATTESTATION_TYPES
from .registry import Registry


def cmd_rotate(args: argparse.Namespace) -> int:
    registry = Registry(args.state)
    did = registry.did_for_key(read_key(args.key))
    if did is None:
        print("error: key does not belong to any registered identity", file=sys.stderr)
        return 2
    identity = registry.rotate(did, key_file=args.key, new_key_file=args.new_key)
    print(
        f"rotated {identity['did']} → new key active "
        f"(version {identity['version']}); DID unchanged"
    )
    return 0


def cmd_agents(args: argparse.Namespace) -> int:
    for identity in Registry(args.state).agents():
        flag = "  [revoked]" if identity["revoked"] else ""
        print(f"{identity['did']}  {identity['display_name']}{flag}")
    return 0


def cmd_disputes(args: argparse.Namespace) -> int:
    registry = Registry(args.state)
    views = registry.disputes_for(args.agent) if args.agent else registry.all_disputes()
    for view in views:
        state = view["outcome"] or view["status"]
        print(f"{view['id']}  {state:<8} agent={view['agent']}  target={view['target']}")
    return 0


def cmd_deal_open(args: argparse.Namespace) -> int:
    entry = Registry(args.state).open_deal(
        payee=args.payee,
        amount_usd=args.amount,
        condition_type=args.condition,
        payer_key_file=args.key,
        payee_key_file=args.payee_key,
        terms=args.terms,
        deadline=args.deadline,
    )
    print(f"opened {entry['id']}: {entry['amount_usd']} USD, payer → payee on {entry['condition_type']}")
    return 0


def cmd_deal_settle(args: argparse.Namespace) -> int:
    entry = Registry(args.state).settle_deal(
        deal=args.deal, settlement=args.settlement, key_file=args.key
    )
    print(f"settled {entry['deal']} against {entry['settlement']}")
    return 0


def cmd_deal_cancel(args: argparse.Namespace) -> int:
    entry = Registry(args.state).cancel_deal(
        deal=args.deal, payer_key_file=args.key, payee_key_file=args.payee_key,
        reason=args.reason,
    )
    print(f"cancelled {entry['deal']} (mutual — no fault assigned)")
    return 0


def cmd_deals(args: argparse.Namespace) -> int:
    for view in Registry(args.state).deals_for(args.agent):
        print(f"{view['id']}  {view['status']:<9} {view['amount_usd']:>10} USD  {view['payer']} → {view['payee']}")
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    jwk = generate_keypair()
    write_key(jwk, args.out)
    print(f"Ed25519 keypair written to {args.out}")
    print(f"derived DID: {did_from_jwk(jwk)}")
    return 0


def cmd_register(args: argparse.Namespace) -> int:
    registry = Registry(args.state)
    identity = registry.register(
        key_file=args.key, display_name=args.name, capabilities=tuple(args.caps)
    )
    print(json.dumps(identity, indent=2))
    return 0


def cmd_attest(args: argparse.Namespace) -> int:
    payload = json.loads(args.payload) if args.payload else {}
    registry = Registry(args.state)
    att = registry.attest(
        agent=args.agent, type_=args.type, key_file=args.key, payload=payload
    )
    print(f"recorded {att.id}: {att.attester} attests {att.type} → {att.agent}")
    print(f"signature: {att.signature[:24]}…" if att.signature else "unsigned")
    return 0


def cmd_query(args: argparse.Namespace) -> int:
    result = Registry(args.state).query(args.agent)
    print(json.dumps(result, indent=2))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    report = Registry(args.state).verify()
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


def cmd_log(args: argparse.Namespace) -> int:
    registry = Registry(args.state)
    for att in registry.attestations_for(agent=args.agent):
        sig = att.signature[:12] + "…" if att.signature else "unsigned"
        print(f"{att.signed_at}  {att.attester} → {att.agent}  {att.type:<20} {sig}")
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    did = did_from_jwk(read_key(args.key))
    identity = Registry(args.state).revoke(did, key_file=args.key)
    print(
        f"revoked {identity['did']} (version {identity['version']}) — "
        "history is kept; new attestations in both directions are refused"
    )
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .api import create_app

    print(
        f"agentcred {__version__} registry API → http://{args.host}:{args.port} "
        f"(state: {args.state})"
    )
    uvicorn.run(create_app(args.state), host=args.host, port=args.port)
    return 0


def cmd_dispute_open(args: argparse.Namespace) -> int:
    registry = Registry(args.state)
    entry = registry.open_dispute(
        target=args.target, reason=args.reason, key_file=args.key, arbiter=args.arbiter
    )
    print(f"opened {entry['id']}: dispute against {entry['agent']} over {entry['target']}")
    return 0


def cmd_dispute_resolve(args: argparse.Namespace) -> int:
    registry = Registry(args.state)
    entry = registry.resolve_dispute(
        dispute=args.dispute, outcome=args.outcome, key_files=args.key
    )
    print(
        f"resolved {entry['dispute']} as {entry['outcome']} — "
        f"signed by {', '.join(entry['resolved_by'])}"
    )
    return 0


def cmd_evidence(args: argparse.Namespace) -> int:
    import json as _json

    bundle = Registry(args.state).evidence_bundle(args.dispute)
    if args.out:
        Path(args.out).write_text(_json.dumps(bundle, indent=2), encoding="utf-8")
        print(f"evidence bundle written to {args.out}")
    else:
        print(_json.dumps(bundle, indent=2))
    return 0


def cmd_verify_bundle(args: argparse.Namespace) -> int:
    import json as _json

    from .evidence import verify_bundle

    bundle = _json.loads(Path(args.file).read_text(encoding="utf-8"))
    report = verify_bundle(bundle)
    print(_json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentcred",
        description="A credit bureau for AI agents — identity, attestations, trust scores.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--state", default="agentcred-state", help="registry state directory (default: ./agentcred-state)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="generate an Ed25519 keypair")
    p.add_argument("--out", required=True, help="path for the private JWK file")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("register", help="register an agent identity from a key file")
    p.add_argument("--key", required=True, help="private JWK file of the agent")
    p.add_argument("--name", default=None, help="display name")
    p.add_argument("--caps", nargs="*", default=[], help="capability strings")
    p.set_defaults(func=cmd_register)

    p = sub.add_parser("attest", help="sign and append an attestation about an agent")
    p.add_argument("--key", required=True, help="attester's private JWK file")
    p.add_argument("--agent", required=True, help="DID of the agent being attested about")
    p.add_argument("--type", required=True, choices=sorted(ATTESTATION_TYPES))
    p.add_argument("--payload", default=None, help="JSON object, e.g. '{\"value_usd\": 120}'")
    p.set_defaults(func=cmd_attest)

    p = sub.add_parser("query", help="show an agent's identity and trust score")
    p.add_argument("--agent", required=True)
    p.set_defaults(func=cmd_query)

    p = sub.add_parser("verify", help="verify log chain and all signatures")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("revoke", help="revoke the identity a key owns (self-service, one-way)")
    p.add_argument("--key", required=True, help="private JWK file of the identity to revoke")
    p.set_defaults(func=cmd_revoke)

    p = sub.add_parser("rotate", help="rotate an identity's key (old key authorizes)")
    p.add_argument("--key", required=True, help="current private JWK file")
    p.add_argument("--new-key", required=True, help="new private JWK file (agentcred keygen)")
    p.set_defaults(func=cmd_rotate)

    p = sub.add_parser("serve", help="run the registry HTTP API (requires the api extra)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("dispute-open", help="open a signed dispute over an attestation")
    p.add_argument("--key", required=True, help="opener's private JWK file")
    p.add_argument("--target", required=True, help="id of the attestation being disputed")
    p.add_argument("--reason", required=True)
    p.add_argument("--arbiter", default=None, help="nominated arbiter DID (enables arbiter mode)")
    p.set_defaults(func=cmd_dispute_open)

    p = sub.add_parser("dispute-resolve", help="resolve a dispute (mutual or arbiter)")
    p.add_argument("--dispute", required=True)
    p.add_argument("--outcome", required=True, choices=["upheld", "rejected", "settled"])
    p.add_argument(
        "--key", action="append", required=True,
        help="resolver key file; repeat for mutual mode (opener + disputed agent)",
    )
    p.set_defaults(func=cmd_dispute_resolve)

    p = sub.add_parser("evidence", help="export a dispute's evidence bundle")
    p.add_argument("--dispute", required=True)
    p.add_argument("--out", default=None, help="write bundle to file instead of stdout")
    p.set_defaults(func=cmd_evidence)

    p = sub.add_parser("verify-bundle", help="offline-verify an evidence bundle")
    p.add_argument("--file", required=True)
    p.set_defaults(func=cmd_verify_bundle)

    p = sub.add_parser("log", help="list attestations (optionally one agent's)")
    p.add_argument("--agent", default=None)
    p.set_defaults(func=cmd_log)

    p = sub.add_parser("agents", help="list registered identities")
    p.set_defaults(func=cmd_agents)

    p = sub.add_parser("disputes", help="list disputes (optionally one agent's)")
    p.add_argument("--agent", default=None)
    p.set_defaults(func=cmd_disputes)

    p = sub.add_parser("deal-open", help="open a mutually-signed deal")
    p.add_argument("--key", required=True, help="payer's private JWK file")
    p.add_argument("--payee-key", required=True, help="payee's private JWK file")
    p.add_argument("--payee", required=True, help="payee DID")
    p.add_argument("--amount", required=True, type=float, help="amount in USD")
    p.add_argument("--condition", required=True, choices=["task_completed", "payment_settled", "capability_verified"])
    p.add_argument("--terms", default="", help="human-readable terms")
    p.add_argument("--deadline", default=None, help="ISO-8601 deadline")
    p.set_defaults(func=cmd_deal_open)

    p = sub.add_parser("deal-settle", help="settle a deal against its condition attestation")
    p.add_argument("--key", required=True, help="payer's (or arbiter's) private JWK file")
    p.add_argument("--deal", required=True)
    p.add_argument("--settlement", required=True, help="id of the condition attestation")
    p.set_defaults(func=cmd_deal_settle)

    p = sub.add_parser("deal-cancel", help="mutually cancel a deal (refund path)")
    p.add_argument("--key", required=True, help="payer's private JWK file")
    p.add_argument("--payee-key", required=True, help="payee's private JWK file")
    p.add_argument("--deal", required=True)
    p.add_argument("--reason", default="")
    p.set_defaults(func=cmd_deal_cancel)

    p = sub.add_parser("deals", help="list deals (optionally one agent's)")
    p.add_argument("--agent", default=None)
    p.set_defaults(func=cmd_deals)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
