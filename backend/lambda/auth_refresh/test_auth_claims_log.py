"""DVP-TSK-983: one `auth_claims` log line wherever an ID token is obtained.

Learn which `amr` Cognito emits for passkey vs password sign-in. The line has
exactly the keys event/path/amr/acr/auth_time/token_use and never carries token
material or anything identifying (sub, email, username, cookie values).
"""
import base64
import importlib.util
import json
import logging
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "shared_layer" / "python"))
sys.path.insert(0, str(HERE.parent / "shared_layer"))
spec = importlib.util.spec_from_file_location("auth_refresh_lf_claims", HERE / "lambda_function.py")
lf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lf)

KEYS = ["event", "path", "amr", "acr", "auth_time", "token_use"]
ORIGIN = "https://enceladus-gamma.jreese.net"
# Synthetic identifying values: none of these may ever reach a log line.
SUB = "11111111-2222-3333-4444-sub-synthetic"
EMAIL = "someone.synthetic@example.invalid"
USERNAME = "synthetic-username-7f3a"
REFRESH_TOKEN = "RT.synthetic-refresh-token-value"
ACCESS_TOKEN = "AT.synthetic-access-token-value"
SIGNATURE = "c2lnbmF0dXJlLXN5bnRoZXRpYy1ub3QtYS1yZWFsLXNpZw"


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def _id_token(**claims) -> str:
    payload = {"sub": SUB, "email": EMAIL, "cognito:username": USERNAME, "token_use": "id", "exp": 4102444800}
    payload.update(claims)
    payload = {k: v for k, v in payload.items() if v is not None}
    return f"{_b64({'alg': 'RS256', 'kid': 'k1'})}.{_b64(payload)}.{SIGNATURE}"


def _material(id_token: str):
    header, payload, sig = id_token.split(".")
    return [id_token, header, payload, sig, SUB, EMAIL, USERNAME, REFRESH_TOKEN, ACCESS_TOKEN]


def _claim_lines(caplog):
    return [r.getMessage() for r in caplog.records if '"event":"auth_claims"' in r.getMessage()]


def _assert_clean(caplog, capsys, id_token):
    out = capsys.readouterr()
    haystack = caplog.text + out.out + out.err
    for secret in _material(id_token):
        assert secret not in haystack, "token material or identifier leaked into captured output"


class _FakeCognito:
    class exceptions:  # noqa: N801
        class NotAuthorizedException(Exception):
            pass

    def __init__(self, id_token):
        self._id_token = id_token

    def initiate_auth(self, **_kw):
        return {"AuthenticationResult": {"IdToken": self._id_token, "AccessToken": ACCESS_TOKEN}}


def _callback(monkeypatch, id_token):
    monkeypatch.setattr(
        lf, "_post_token_exchange",
        lambda domain, code: {"id_token": id_token, "refresh_token": REFRESH_TOKEN, "access_token": ACCESS_TOKEN},
    )
    return lf.lambda_handler({
        "requestContext": {"http": {"method": "GET", "path": "/api/v1/auth/callback"}},
        "queryStringParameters": {"code": "synthetic-one-time-code", "state": ""},
        "headers": {},
    }, None)


def _refresh(monkeypatch, id_token, kit):
    monkeypatch.setattr(lf, "_cognito", _FakeCognito(id_token))
    headers = {"origin": ORIGIN}
    if kit:
        headers["x-requested-with"] = "io-kit"
    return lf.lambda_handler({
        "requestContext": {"http": {"method": "POST", "path": "/api/v1/auth/refresh"}},
        "headers": headers,
        "cookies": [f"enceladus_refresh_token={REFRESH_TOKEN}"],
    }, None)


def test_callback_logs_one_line_with_exactly_the_documented_keys(monkeypatch, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    tok = _id_token(amr=["swk", "hwk"], acr="1", auth_time=1760000000)
    r = _callback(monkeypatch, tok)
    assert r["statusCode"] == 302 and any(c.startswith("enceladus_id_token=") for c in r["cookies"])
    lines = _claim_lines(caplog)
    assert len(lines) == 1
    assert lines[0] == '{"event":"auth_claims","path":"callback","amr":["swk","hwk"],"acr":"1","auth_time":1760000000,"token_use":"id"}'
    assert list(json.loads(lines[0])) == KEYS
    _assert_clean(caplog, capsys, tok)


@pytest.mark.parametrize("kit", [False, True])
def test_refresh_grant_logs_one_line_on_both_refresh_routes(monkeypatch, caplog, capsys, kit):
    caplog.set_level(logging.DEBUG)
    tok = _id_token(amr=["pwd"], auth_time=1760000123)
    r = _refresh(monkeypatch, tok, kit)
    assert r["statusCode"] == 200
    lines = _claim_lines(caplog)
    assert len(lines) == 1
    assert json.loads(lines[0]) == {
        "event": "auth_claims", "path": "refresh", "amr": ["pwd"], "acr": None,
        "auth_time": 1760000123, "token_use": "id",
    }
    assert list(json.loads(lines[0])) == KEYS
    _assert_clean(caplog, capsys, tok)


def test_missing_claims_are_null_and_token_use_falls_back(monkeypatch, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    tok = _id_token(token_use=None)
    _callback(monkeypatch, tok)
    rec = json.loads(_claim_lines(caplog)[0])
    assert rec == {"event": "auth_claims", "path": "callback", "amr": None, "acr": None,
                   "auth_time": None, "token_use": "unknown"}
    _assert_clean(caplog, capsys, tok)


def test_undecodable_token_still_logs_nulls_and_never_breaks_the_login(monkeypatch, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    r = _callback(monkeypatch, "not-a-jwt")
    assert r["statusCode"] == 302 and r["cookies"]
    rec = json.loads(_claim_lines(caplog)[0])
    assert rec["amr"] is None and rec["acr"] is None and rec["auth_time"] is None and rec["token_use"] == "unknown"
    _assert_clean(caplog, capsys, _id_token())


def test_odd_claim_shapes_are_sanitised(monkeypatch, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    tok = _id_token(amr="pwd", acr=5, auth_time="soon", token_use=7)
    _callback(monkeypatch, tok)
    rec = json.loads(_claim_lines(caplog)[0])
    assert rec == {"event": "auth_claims", "path": "callback", "amr": None, "acr": None,
                   "auth_time": None, "token_use": "unknown"}
    caplog.clear()
    tok = _id_token(amr=["pwd", 3, {"sub": SUB}, "x" * 100], auth_time=True)
    _callback(monkeypatch, tok)
    rec = json.loads(_claim_lines(caplog)[0])
    assert rec["amr"] == ["pwd", "x" * 32]
    assert rec["auth_time"] is None
    _assert_clean(caplog, capsys, tok)


def test_failed_exchange_or_refresh_logs_no_claims(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)

    def boom(domain, code):
        raise lf._TokenExchangeFailed("token_exchange_failed", "invalid_grant")

    monkeypatch.setattr(lf, "_post_token_exchange", boom)
    r = lf.lambda_handler({
        "requestContext": {"http": {"method": "GET", "path": "/api/v1/auth/callback"}},
        "queryStringParameters": {"code": "x"}, "headers": {},
    }, None)
    assert r["statusCode"] == 302
    assert _claim_lines(caplog) == []
