"""ENC-FTR-074 Ph2 (ENC-TSK-I80) — unit tests for the REQUEST-type Lambda authorizer.

The authorizer handler is embedded inline (ZipFile) in
``infrastructure/cloudformation/08-agent-auth.yaml`` (single source of truth, matching the
Ph1 inline-handler pattern). These tests extract that inline code, exec it as a module, and
exercise:

  * the hand-rolled pure-stdlib RS256 verification against a generated RSA JWKS,
  * three-principal discrimination (internal-key / human JWT / M2M scope token),
  * the route-tier governance-authority boundary (agent.standard denied on Tier 0, admitted
    on Tier 1).

Test vectors are built with PyJWT + cryptography (dev-only deps); the Lambda itself uses
neither at runtime.
"""

import base64
import os
import pathlib
import time

import jwt as pyjwt
import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric import rsa

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TEMPLATE = REPO_ROOT / "infrastructure" / "cloudformation" / "08-agent-auth.yaml"

AGENT_POOL = "us-west-2_AgentPoolTest"
HUMAN_POOL = "us-east-1_HumanPoolTest"
_KID = "test-kid-1"


class _CfnLoader(yaml.SafeLoader):
    pass


_CfnLoader.add_multi_constructor("!", lambda loader, suffix, node: None)


def _b64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def authorizer(rsa_key):
    os.environ["AGENT_USER_POOL_ID"] = AGENT_POOL
    os.environ["HUMAN_USER_POOL_ID"] = HUMAN_POOL
    os.environ["AGENT_M2M_CLIENT_ID"] = "m2mclient123"
    os.environ["INTERNAL_KEY_SECRET_ID"] = ""

    doc = yaml.load(TEMPLATE.read_text(), Loader=_CfnLoader)
    code = doc["Resources"]["AgentAuthorizerLambda"]["Properties"]["Code"]["ZipFile"]
    ns: dict = {}
    exec(compile(code, "agent_authorizer_inline", "exec"), ns)  # noqa: S102

    pub = rsa_key.public_key().public_numbers()
    jwks = {AGENT_POOL: {_KID: (pub.n, pub.e)}, HUMAN_POOL: {_KID: (pub.n, pub.e)}}
    ns["_get_jwks"] = lambda pool_id: jwks[pool_id]
    return ns


def _make_token(rsa_key, pool, claims):
    payload = {
        "iss": f"https://cognito-idp.{pool.split('_', 1)[0]}.amazonaws.com/{pool}",
        "exp": int(time.time()) + 600,
        "iat": int(time.time()),
        "sub": "sub-123",
    }
    payload.update(claims)
    return pyjwt.encode(payload, rsa_key, algorithm="RS256", headers={"kid": _KID})


def _event(route_key, *, bearer=None, cookie=None, internal_key=None):
    headers = {}
    if bearer:
        headers["authorization"] = f"Bearer {bearer}"
    if cookie:
        headers["cookie"] = cookie
    if internal_key:
        headers["x-coordination-internal-key"] = internal_key
    method, path = route_key.split(" ", 1)
    return {
        "version": "2.0",
        "routeKey": route_key,
        "headers": headers,
        "requestContext": {"http": {"method": method, "path": path}, "routeKey": route_key},
    }


TIER1 = "POST /api/v1/agent/selftest/standard"
TIER0 = "POST /api/v1/agent/selftest/admin"


def test_m2m_standard_admitted_on_tier1(authorizer, rsa_key):
    token = _make_token(
        rsa_key, AGENT_POOL,
        {"token_use": "access", "scope": "enceladus-api/agent.standard",
         "client_id": "m2mclient123", "enc:agent_tier": "standard",
         "enc:session_id": "ENC-SES-TST"},
    )
    res = authorizer["handler"](_event(TIER1, bearer=token), None)
    assert res["isAuthorized"] is True
    assert res["context"]["principalType"] == "m2m"
    assert res["context"]["agentTier"] == "standard"
    assert res["context"]["sessionId"] == "ENC-SES-TST"


def test_m2m_standard_rejected_on_tier0(authorizer, rsa_key):
    token = _make_token(
        rsa_key, AGENT_POOL,
        {"token_use": "access", "scope": "enceladus-api/agent.standard",
         "client_id": "m2mclient123", "enc:agent_tier": "standard"},
    )
    res = authorizer["handler"](_event(TIER0, bearer=token), None)
    assert res["isAuthorized"] is False
    assert res["context"]["requiredTier"] == "elevated"


def test_m2m_elevated_admitted_on_tier0(authorizer, rsa_key):
    token = _make_token(
        rsa_key, AGENT_POOL,
        {"token_use": "access", "scope": "enceladus-api/agent.elevated",
         "client_id": "m2mclient123", "enc:agent_tier": "elevated"},
    )
    res = authorizer["handler"](_event(TIER0, bearer=token), None)
    assert res["isAuthorized"] is True


def test_tier_derived_from_scope_when_claim_absent(authorizer, rsa_key):
    token = _make_token(
        rsa_key, AGENT_POOL,
        {"token_use": "access", "scope": "enceladus-api/agent.elevated"},
    )
    res = authorizer["handler"](_event(TIER0, bearer=token), None)
    assert res["isAuthorized"] is True
    assert res["context"]["agentTier"] == "elevated"


def test_human_jwt_is_admin_and_admitted_on_tier0(authorizer, rsa_key):
    token = _make_token(rsa_key, HUMAN_POOL, {"token_use": "id", "aud": "webui"})
    res = authorizer["handler"](_event(TIER0, bearer=token), None)
    assert res["isAuthorized"] is True
    assert res["context"]["principalType"] == "human"


def test_human_cookie_token_is_accepted(authorizer, rsa_key):
    token = _make_token(rsa_key, HUMAN_POOL, {"token_use": "id", "aud": "webui"})
    res = authorizer["handler"](_event(TIER1, cookie=f"enceladus_id_token={token}"), None)
    assert res["isAuthorized"] is True
    assert res["context"]["principalType"] == "human"


def test_tampered_signature_is_rejected(authorizer, rsa_key):
    token = _make_token(
        rsa_key, AGENT_POOL,
        {"token_use": "access", "scope": "enceladus-api/agent.elevated",
         "enc:agent_tier": "elevated"},
    )
    tampered = token[:-4] + ("AAAA" if token[-4:] != "AAAA" else "BBBB")
    res = authorizer["handler"](_event(TIER1, bearer=tampered), None)
    assert res["isAuthorized"] is False


def test_unknown_issuer_is_rejected(authorizer, rsa_key):
    token = _make_token(
        rsa_key, "us-west-2_StrangerPool",
        {"token_use": "access", "scope": "enceladus-api/agent.admin"},
    )
    res = authorizer["handler"](_event(TIER1, bearer=token), None)
    assert res["isAuthorized"] is False
    assert res["context"]["principalType"] == "unknown"


def test_no_credentials_is_rejected(authorizer):
    res = authorizer["handler"](_event(TIER1), None)
    assert res["isAuthorized"] is False
    assert res["context"]["principalType"] == "anonymous"


def test_internal_key_admitted_when_configured(authorizer, monkeypatch):
    monkeypatch.setitem(authorizer, "_internal_key_cache", None)
    monkeypatch.setitem(authorizer, "INTERNAL_KEY_SECRET_ID", "secret-arn")
    monkeypatch.setitem(authorizer, "_load_internal_key", lambda: "s3cr3t-key")
    res = authorizer["handler"](_event(TIER0, internal_key="s3cr3t-key"), None)
    assert res["isAuthorized"] is True
    assert res["context"]["principalType"] == "internal"


def test_internal_key_wrong_value_rejected(authorizer, monkeypatch):
    monkeypatch.setitem(authorizer, "_load_internal_key", lambda: "s3cr3t-key")
    res = authorizer["handler"](_event(TIER1, internal_key="WRONG"), None)
    assert res["isAuthorized"] is False
    assert res["context"]["principalType"] == "internal"


def test_get_read_route_allows_observe(authorizer, rsa_key):
    token = _make_token(
        rsa_key, AGENT_POOL,
        {"token_use": "access", "scope": "enceladus-api/agent.observe",
         "enc:agent_tier": "observe"},
    )
    ev = _event("GET /api/v1/tracker/enceladus", bearer=token)
    res = authorizer["handler"](ev, None)
    assert res["isAuthorized"] is True
    assert res["context"]["requiredTier"] == "observe"
