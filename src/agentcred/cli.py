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

    p = sub.add_parser("log", help="list attestations (optionally one agent's)")
    p.add_argument("--agent", default=None)
    p.set_defaults(func=cmd_log)

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
