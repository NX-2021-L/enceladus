"""ENC-TSK-Q83: thin passkey routes (list / fresh-auth / delete) on the auth lambda."""
import base64
import datetime
import importlib.util
import json
import pathlib
import sys
import time

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "shared_layer" / "python"))
sys.path.insert(0, str(HERE.parent / "shared_layer"))
spec = importlib.util.spec_from_file_location("auth_refresh_lf_q83", HERE / "lambda_function.py")
lf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lf)

ORIGIN = "https://enceladus.jreese.net"
RT = "RT.synthetic-refresh"


def _jwt(claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    return f"{enc({'alg': 'none'})}.{enc(claims)}.sig"


class _Cognito:
    def __init__(self, creds):
        self.creds = creds
        self.deleted = []

    def list_web_authn_credentials(self, **kw):
        assert kw["AccessToken"] == "AT"
        return {"Credentials": list(self.creds)}

    def delete_web_authn_credential(self, **kw):
        self.deleted.append(kw["CredentialId"])


def _cred(i):
    return {"CredentialId": f"cred-{i}", "FriendlyCredentialName": f"Key {i}",
            "CreatedAt": datetime.datetime(2026, 1, i, tzinfo=datetime.timezone.utc)}


@pytest.fixture
def env(monkeypatch):
    state = {"auth_time": int(time.time()) - 10, "cog": _Cognito([_cred(1), _cred(2)])}
    monkeypatch.setattr(lf, "_refresh_tokens", lambda rt: {
        "id_token": _jwt({"sub": "u1", "auth_time": state["auth_time"]}), "access_token": "AT"})
    monkeypatch.setattr(lf, "_get_cognito", lambda: state["cog"])
    return state


def _ev(method, path, headers=None, kit=True, origin=ORIGIN, cookie=True):
    h = {"origin": origin} if origin else {}
    if kit:
        h["x-requested-with"] = "io-kit"
    h.update(headers or {})
    return {"requestContext": {"http": {"method": method, "path": path}}, "headers": h,
            "cookies": [f"enceladus_refresh_token={RT}"] if cookie else []}


def _call(method, path, **kw):
    r = lf.lambda_handler(_ev(method, path, **kw), None)
    return r["statusCode"], (json.loads(r["body"]) if r["body"] else None)


def _proof(env):
    return _call("GET", "/api/v1/auth/passkeys/fresh-auth")[1]["proof"]


def test_list_mapping(env):
    code, body = _call("GET", "/api/v1/auth/passkeys")
    assert code == 200
    assert body["passkeys"][0] == {"credential_id": "cred-1", "friendly_name": "Key 1",
                                   "created_at": "2026-01-01T00:00:00+00:00", "last_used_at": None}
    assert len(body["passkeys"]) == 2


def test_gate_and_missing_session(env):
    assert _call("GET", "/api/v1/auth/passkeys", kit=False)[0] == 403
    assert _call("GET", "/api/v1/auth/passkeys", origin="https://evil.example")[0] == 403
    assert _call("GET", "/api/v1/auth/passkeys", cookie=False)[0] == 401


def test_fresh_auth_fresh_and_stale(env):
    code, body = _call("GET", "/api/v1/auth/passkeys/fresh-auth")
    assert (code, body["fresh"], body["auth_time"]) == (200, True, env["auth_time"])
    assert body["proof"]
    env["auth_time"] = int(time.time()) - 4000
    body = _call("GET", "/api/v1/auth/passkeys/fresh-auth")[1]
    assert (body["fresh"], body["proof"]) == (False, None)


def test_delete_requires_fresh_auth(env):
    assert _call("DELETE", "/api/v1/auth/passkeys/cred-1") == (401, {"error": "fresh_auth_required"})
    assert _call("DELETE", "/api/v1/auth/passkeys/cred-1", headers={"x-fresh-auth": "1.deadbeef"})[0] == 401
    stale = lf._fresh_auth_proof(RT, "u1", env["auth_time"], int(time.time()) - 301)
    assert _call("DELETE", "/api/v1/auth/passkeys/cred-1", headers={"x-fresh-auth": stale})[0] == 401
    other = lf._fresh_auth_proof("RT.other", "u1", env["auth_time"], int(time.time()))
    assert _call("DELETE", "/api/v1/auth/passkeys/cred-1", headers={"x-fresh-auth": other})[0] == 401
    assert env["cog"].deleted == []


def test_delete_last_passkey_409(env):
    env["cog"].creds = [_cred(1)]
    code, body = _call("DELETE", "/api/v1/auth/passkeys/cred-1", headers={"x-fresh-auth": _proof(env)})
    assert (code, body) == (409, {"error": "last_passkey"})
    assert env["cog"].deleted == []


def test_delete_happy_and_unknown(env):
    p = _proof(env)
    assert _call("DELETE", "/api/v1/auth/passkeys/cred-2", headers={"x-fresh-auth": p}) == (204, None)
    assert env["cog"].deleted == ["cred-2"]
    assert _call("DELETE", "/api/v1/auth/passkeys/nope", headers={"x-fresh-auth": p})[0] == 404
