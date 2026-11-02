"""Tests for the reference HTTP registry API (v0.3).

Runs under pytest, or standalone: python tests/test_api.py
Clients sign locally (spec §7) and submit; the server never sees keys.
"""

from __future__ import annotations

import contextlib
import io
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from fastapi.testclient import TestClient  # noqa: E402

from agentcred.api import create_app  # noqa: E402
from agentcred.canonical import canonical  # noqa: E402
from agentcred.crypto import did_from_jwk, generate_keypair, sign  # noqa: E402
from agentcred.models import Attestation  # noqa: E402


def make_client(tmp: str) -> TestClient:
    return TestClient(create_app(str(Path(tmp) / "state")))


def register(client: TestClient, name: str) -> tuple[dict, str]:
    jwk = generate_keypair()
    public = {k: jwk[k] for k in ("kty", "crv", "x")}
    response = client.post(
        "/agents", json={"public_jwk": public, "display_name": name}
    )
    assert response.status_code == 201, response.text
    did = response.json()["did"]
    assert did == did_from_jwk(jwk)
    return jwk, did


def signed_attestation(attester_jwk: dict, agent: str, type_: str, payload: dict | None = None) -> dict:
    att = Attestation(
        id="att_api1",
        agent=agent,
        attester=did_from_jwk(attester_jwk),
        type=type_,
        signed_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        payload=payload or {},
    )
    sig = sign(canonical(att.unsigned_dict()), attester_jwk)
    return att.to_dict() | {"signature": sig}


def test_index_and_health():
    with tempfile.TemporaryDirectory() as tmp:
        client = make_client(tmp)
        assert client.get("/").json()["name"] == "agentcred"
        assert client.get("/health").json()["ok"] is True


def test_state_dir_resolves_from_env():
    import os

    with tempfile.TemporaryDirectory() as tmp:
        state = str(Path(tmp) / "from-env")
        old = os.environ.get("AGENTCRED_STATE")
        os.environ["AGENTCRED_STATE"] = state
        try:
            client = TestClient(create_app())  # no explicit dir → env
            jwk = generate_keypair()
            public = {k: jwk[k] for k in ("kty", "crv", "x")}
            response = client.post("/agents", json={"public_jwk": public})
            assert response.status_code == 201
            assert Path(state, "agents.json").exists()
        finally:
            if old is None:
                os.environ.pop("AGENTCRED_STATE", None)
            else:
                os.environ["AGENTCRED_STATE"] = old


def test_register_conflict():
    with tempfile.TemporaryDirectory() as tmp:
        client = make_client(tmp)
        jwk, _ = register(client, "bot")
        public = {k: jwk[k] for k in ("kty", "crv", "x")}
        again = client.post("/agents", json={"public_jwk": public})
        assert again.status_code == 409


def test_full_flow_attest_query_verify():
    with tempfile.TemporaryDirectory() as tmp:
        client = make_client(tmp)
        _, seller_did = register(client, "invoice-bot")
        buyer_jwk, _ = register(client, "payer-bot")

        body = signed_attestation(
            buyer_jwk, seller_did, "payment_settled", {"value_usd": 250.0}
        )
        response = client.post("/attestations", json=body)
        assert response.status_code == 201, response.text

        report = client.get(f"/agents/{seller_did}").json()
        assert report["metrics"]["volume_usd"] == 250.0
        assert report["identity"]["display_name"] == "invoice-bot"

        history = client.get(f"/agents/{seller_did}/attestations").json()
        assert len(history["attestations"]) == 1

        audit = client.get("/verify").json()
        assert audit["ok"] and audit["signatures_valid"] == 1


def test_tampered_signature_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        client = make_client(tmp)
        _, seller_did = register(client, "seller")
        buyer_jwk, _ = register(client, "buyer")
        body = signed_attestation(buyer_jwk, seller_did, "task_completed")
        body["payload"]["task"] = "something-else"  # signed payload mutated
        response = client.post("/attestations", json=body)
        assert response.status_code == 400


def test_unknown_agent_and_attester():
    with tempfile.TemporaryDirectory() as tmp:
        client = make_client(tmp)
        assert client.get("/agents/did:agentcred:nobody").status_code == 404
        buyer_jwk, _ = register(client, "buyer")
        body = signed_attestation(buyer_jwk, "did:agentcred:ghost", "task_completed")
        response = client.post("/attestations", json=body)
        assert response.status_code == 404


def test_unsigned_and_future_dated_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        client = make_client(tmp)
        _, seller_did = register(client, "seller")
        buyer_jwk, _ = register(client, "buyer")

        body = signed_attestation(buyer_jwk, seller_did, "task_completed")
        body.pop("signature")
        assert client.post("/attestations", json=body).status_code == 400

        future = signed_attestation(buyer_jwk, seller_did, "task_completed")
        future["signed_at"] = (
            datetime.now(timezone.utc) + timedelta(hours=1)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        future["signature"] = sign(
            canonical(
                {k: future[k] for k in ("id", "agent", "attester", "type", "signed_at", "payload")}
            ),
            buyer_jwk,
        )
        response = client.post("/attestations", json=future)
        assert response.status_code == 400


def test_revocation_via_api():
    with tempfile.TemporaryDirectory() as tmp:
        client = make_client(tmp)
        seller_jwk, seller_did = register(client, "seller")
        buyer_jwk, _ = register(client, "buyer")

        intent = canonical({"action": "revoke", "agent": seller_did})
        wrong = client.post(
            f"/agents/{seller_did}/revoke", json={"signature": sign(intent, buyer_jwk)}
        )
        assert wrong.status_code == 400  # buyer can't revoke seller

        ok = client.post(
            f"/agents/{seller_did}/revoke", json={"signature": sign(intent, seller_jwk)}
        )
        assert ok.status_code == 200 and ok.json()["revoked"] is True

        again = client.post(
            f"/agents/{seller_did}/revoke", json={"signature": sign(intent, seller_jwk)}
        )
        assert again.status_code == 409

        body = signed_attestation(buyer_jwk, seller_did, "task_completed")
        assert client.post("/attestations", json=body).status_code == 409

        flags = client.get(f"/agents/{seller_did}").json()["flags"]
        assert "revoked" in flags


def test_invalid_type_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        client = make_client(tmp)
        _, seller_did = register(client, "seller")
        buyer_jwk, _ = register(client, "buyer")
        # hand-built body: a hostile client bypassing the client-side models
        unsigned = {
            "id": "att_badtype",
            "agent": seller_did,
            "attester": did_from_jwk(buyer_jwk),
            "type": "made_up_type",
            "signed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "payload": {},
        }
        body = unsigned | {"signature": sign(canonical(unsigned), buyer_jwk)}
        assert client.post("/attestations", json=body).status_code == 400


def test_dispute_flow_via_api():
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "src"))
    from agentcred.evidence import verify_bundle

    with tempfile.TemporaryDirectory() as tmp:
        client = make_client(tmp)
        seller_jwk, seller_did = register(client, "seller")
        buyer_jwk, buyer_did = register(client, "buyer")

        att = signed_attestation(buyer_jwk, seller_did, "task_completed")
        posted = client.post("/attestations", json=att).json()["attestation"]

        core = {
            "kind": "dispute.opened",
            "id": "dsp_api1",
            "target": posted["id"],
            "agent": seller_did,
            "opened_by": buyer_did,
            "reason": "task not actually completed",
            "opened_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "arbiter": None,
        }
        response = client.post(
            "/disputes", json=core | {"signature": sign(canonical(core), buyer_jwk)}
        )
        assert response.status_code == 201, response.text

        # one-sided resolution is refused
        res_core = {
            "kind": "dispute.resolved",
            "dispute": "dsp_api1",
            "outcome": "rejected",
            "resolved_by": [buyer_did],
            "resolved_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        one_sided = client.post(
            "/disputes/dsp_api1/resolve",
            json=res_core | {"signatures": [sign(canonical(res_core), buyer_jwk)]},
        )
        assert one_sided.status_code == 400

        mutual_core = res_core | {"resolved_by": [buyer_did, seller_did]}
        resolved = client.post(
            "/disputes/dsp_api1/resolve",
            json=mutual_core
            | {
                "signatures": [
                    sign(canonical(mutual_core), buyer_jwk),
                    sign(canonical(mutual_core), seller_jwk),
                ]
            },
        )
        assert resolved.status_code == 201, resolved.text

        view = client.get("/disputes/dsp_api1").json()
        assert view["status"] == "resolved" and view["outcome"] == "rejected"

        bundle = client.get("/disputes/dsp_api1/evidence").json()
        report = verify_bundle(bundle)
        assert report["ok"], report["problems"]
        assert report["signatures_valid"] == 4

        # false accusation lifted: seller's score unaffected by the dispute
        report_card = client.get(f"/agents/{seller_did}").json()
        assert report_card["metrics"]["disputes_lifted"] == 1
        assert report_card["metrics"]["disputes_upheld"] == 0


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf):
                    fn()
                print(f"PASS {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
    sys.exit(1 if failures else 0)
