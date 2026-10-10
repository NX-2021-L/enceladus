"""DVP-TSK-861: auth_refresh as the @io-kit/auth edge (AUTH-C refresh/manifest contract)."""
import base64
import importlib.util
import json
import pathlib
import sys
import time

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "shared_layer" / "python"))
sys.path.insert(0, str(HERE.parent / "shared_layer"))
spec = importlib.util.spec_from_file_location("auth_refresh_lf", HERE / "lambda_function.py")
lf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lf)

ORIGIN = "https://enceladus.jreese.net"


def _jwt(claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")  # noqa: E731
    return f"{enc({'alg': 'none'})}.{enc(claims)}.sig"


def _event(method="POST", path="/api/v1/auth/refresh", headers=None, cookies=None):
    return {"requestContext": {"http": {"method": method, "path": path}},
            "headers": headers or {}, "cookies": cookies or []}


KIT = {"x-requested-with": "io-kit", "origin": ORIGIN}
RT = ["enceladus_refresh_token=rt-1"]


def test_refresh_success_returns_kit_body_and_cookies(monkeypatch):
    exp = int(time.time()) + 3600
    idt = _jwt({"exp": exp, "sub": "u"})
    monkeypatch.setattr(lf, "_refresh_tokens", lambda rt: {"id_token": idt, "access_token": "at"})
    r = lf.lambda_handler(_event(headers=KIT, cookies=RT), None)
    body = json.loads(r["body"])
    assert r["statusCode"] == 200
    assert body["accessToken"] == "at" and body["idToken"] == idt and body["exp"] == exp
    assert any(c.startswith("enceladus_id_token=") and "HttpOnly" in c for c in r["cookies"])
    assert r["headers"]["Cache-Control"] == "no-store"


def test_refresh_rejected_is_401_and_clears_cookies(monkeypatch):
    def boom(rt):
        raise lf.RefreshRejected("revoked")
    monkeypatch.setattr(lf, "_refresh_tokens", boom)
    r = lf.lambda_handler(_event(headers=KIT, cookies=RT), None)
    assert r["statusCode"] == 401 and json.loads(r["body"])["code"] == "AUTH_REFRESH_FAILED"
    assert all("Max-Age=0" in c for c in r["cookies"])


def test_refresh_network_is_503_and_keeps_cookie(monkeypatch):
    def boom(rt):
        raise lf.RefreshNetwork("timeout")
    monkeypatch.setattr(lf, "_refresh_tokens", boom)
    r = lf.lambda_handler(_event(headers=KIT, cookies=RT), None)
    assert r["statusCode"] == 503 and json.loads(r["body"])["code"] == "AUTH_NETWORK"
    assert "cookies" not in r


def test_refresh_without_cookie_is_401():
    r = lf.lambda_handler(_event(headers=KIT), None)
    assert r["statusCode"] == 401 and json.loads(r["body"])["code"] == "AUTH_REFRESH_FAILED"


def test_refresh_foreign_origin_is_403():
    r = lf.lambda_handler(_event(headers={"x-requested-with": "io-kit", "origin": "https://evil.example"}, cookies=RT), None)
    assert r["statusCode"] == 403 and json.loads(r["body"])["code"] == "AUTH_FORBIDDEN"


def test_legacy_refresh_without_kit_header_is_unchanged(monkeypatch):
    monkeypatch.setattr(lf, "_refresh_tokens", lambda rt: {"id_token": "i", "access_token": "a"})
    r = lf.lambda_handler(_event(cookies=RT), None)
    assert r["statusCode"] == 200 and json.loads(r["body"]) == {"success": True, "expires_in": lf.ID_TOKEN_MAX_AGE}


def test_manifest_issued_from_policy_table_for_admin():
    idt = _jwt({"exp": int(time.time()) + 600, "sub": "u", "iss": "https://x/" + lf.COGNITO_USER_POOL_ID,
                "cognito:groups": ["io-dev-admin"]})
    r = lf.lambda_handler(_event("GET", "/api/v1/auth/manifest", cookies=[f"enceladus_id_token={idt}"]), None)
    m = json.loads(r["body"])
    assert r["statusCode"] == 200
    caps = json.loads((HERE.parents[2] / "tools/enceladus-mcp-server/parity/caps.json").read_text())
    assert {g["action"] for g in m["grants"]} == {a["name"] for a in caps["actions"]}  # table covers caps.json
    assert all(g["modes"] == ["dry_run", "execute"] for g in m["grants"])
    assert m["principal"]["groups"] == ["io-dev-admin"]


def test_manifest_denies_execute_without_group():
    idt = _jwt({"exp": int(time.time()) + 600, "sub": "u", "cognito:groups": ["reader"]})
    r = lf.lambda_handler(_event("GET", "/api/v1/auth/manifest", headers={"authorization": f"Bearer {idt}"}), None)
    assert all(g["modes"] == [] for g in json.loads(r["body"])["grants"])


def test_manifest_requires_live_token():
    r = lf.lambda_handler(_event("GET", "/api/v1/auth/manifest"), None)
    assert r["statusCode"] == 401
    old = _jwt({"exp": int(time.time()) - 5})
    r = lf.lambda_handler(_event("GET", "/api/v1/auth/manifest", cookies=[f"enceladus_id_token={old}"]), None)
    assert r["statusCode"] == 401 and json.loads(r["body"])["code"] == "AUTH_EXPIRED"
