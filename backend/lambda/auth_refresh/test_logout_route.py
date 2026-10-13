"""DVP-TSK-B41: POST /api/v1/auth/logout, a logout that actually logs out.

The refresh token lives in an HttpOnly cookie the page cannot touch, so the
only way to end the session is for this Lambda to (a) revoke the token at
Cognito, best-effort, and (b) clear EVERY cookie it sets with the exact
Path/attributes they were set with. The route must also be declared on the HTTP
API, wired to the auth-refresh integration, and carry the same CSRF/origin gate
as the kit refresh route.
"""
import importlib.util
import json
import logging
import pathlib
import re
import sys
import urllib.error
from urllib.parse import parse_qs, urlparse

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "shared_layer" / "python"))
sys.path.insert(0, str(HERE.parent / "shared_layer"))
spec = importlib.util.spec_from_file_location("auth_refresh_lf_logout", HERE / "lambda_function.py")
lf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lf)

ROOT = HERE.parents[2]
HOSTED = "https://auth.enceladus.jreese.net"
ORIGIN = "https://enceladus-gamma.jreese.net"
REFRESH_TOKEN = "RT.secret-refresh-value-DO-NOT-LOG"  # synthetic, never a real token


def _event(origin=ORIGIN, kit=True, cookies=None, method="POST", path="/api/v1/auth/logout"):
    headers = {}
    if origin is not None:
        headers["origin"] = origin
    if kit:
        headers["x-requested-with"] = "io-kit"
    ev = {"requestContext": {"http": {"method": method, "path": path}}, "headers": headers, "cookies": []}
    if cookies is None:
        cookies = [f"enceladus_refresh_token={REFRESH_TOKEN}", "enceladus_id_token=ID.synthetic.value"]
    ev["cookies"] = cookies
    return ev


class _Resp:
    def read(self):
        return b""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def revoke_calls(monkeypatch):
    calls = []

    def fake_urlopen(req, timeout=None):
        calls.append(req)
        return _Resp()

    monkeypatch.setattr(lf.urllib.request, "urlopen", fake_urlopen)
    return calls


def _name_attrs(set_cookie):
    head, *attrs = [p.strip() for p in set_cookie.split(";")]
    return head.split("=", 1)[0], head.split("=", 1)[1], attrs


def test_clears_every_auth_cookie_with_the_attributes_they_were_set_with(revoke_calls):
    r = lf.lambda_handler(_event(), None)
    assert r["statusCode"] == 200
    cleared = {}
    for c in r["cookies"]:
        name, value, attrs = _name_attrs(c)
        assert value == ""
        assert "Max-Age=0" in attrs
        cleared[name] = attrs
    # The three cookies the callback / refresh routes set, byte-for-byte attributes.
    assert cleared == {
        "enceladus_id_token": ["Path=/", "Secure", "HttpOnly", "SameSite=None", "Max-Age=0"],
        "enceladus_refresh_token": ["Path=/", "Secure", "HttpOnly", "SameSite=None", "Max-Age=0"],
        "enceladus_session_at": ["Path=/enceladus", "Secure", "SameSite=None", "Max-Age=0"],
    }
    # No Domain anywhere: host-scoped cookies must be cleared host-scoped.
    assert not any("Domain=" in c for c in r["cookies"])


def test_cleared_set_matches_every_cookie_the_lambda_sets():
    """If a route starts setting a new cookie, logout must clear it too."""
    src = (HERE / "lambda_function.py").read_text()
    set_names = set(re.findall(r'f?"(enceladus_[a-z_]+)=', src))
    assert set_names == {"enceladus_id_token", "enceladus_refresh_token", "enceladus_session_at"}
    assert {c.split("=", 1)[0] for c in lf._clear_cookies()} == set_names


def _logout_url_parts(r):
    body = json.loads(r["body"])
    assert body["logged_out"] is True
    loc = urlparse(body["logout_url"])
    return loc, {k: v[0] for k, v in parse_qs(loc.query).items()}


def test_response_shape_and_headers(revoke_calls):
    r = lf.lambda_handler(_event(), None)
    assert r["statusCode"] == 200
    assert set(json.loads(r["body"])) == {"logged_out", "logout_url"}
    assert r["headers"]["Cache-Control"] == "no-store"
    assert r["headers"]["Access-Control-Allow-Origin"] == ORIGIN


@pytest.mark.parametrize("redirect_uri,expected", [
    ("https://enceladus-gamma.jreese.net/api/v1/auth/callback", "https://enceladus-gamma.jreese.net/"),
    ("https://enceladus.jreese.net/api/v1/auth/callback", "https://enceladus.jreese.net/"),
])
def test_logout_url_is_hosted_ui_logout_with_origin_of_redirect_uri(monkeypatch, revoke_calls, redirect_uri, expected):
    monkeypatch.setattr(lf, "WEBUI_OAUTH_REDIRECT_URI", redirect_uri)
    loc, q = _logout_url_parts(lf.lambda_handler(_event(), None))
    assert f"{loc.scheme}://{loc.netloc}" == HOSTED
    assert loc.path == "/logout"
    assert q == {"client_id": lf.COGNITO_CLIENT_ID, "logout_uri": expected}


@pytest.mark.parametrize("value", ["", "true", "TRUE", "1", "anything"])
def test_kill_switch_unset_or_true_keeps_the_hosted_logout_on(monkeypatch, revoke_calls, value):
    monkeypatch.setattr(lf, "COGNITO_HOSTED_LOGOUT", value)
    assert json.loads(lf.lambda_handler(_event(), None)["body"])["logout_url"] is not None


@pytest.mark.parametrize("value", ["false", "False", " false "])
def test_kill_switch_false_returns_null_logout_url_but_still_logs_out(monkeypatch, revoke_calls, value):
    monkeypatch.setattr(lf, "COGNITO_HOSTED_LOGOUT", value)
    r = lf.lambda_handler(_event(), None)
    assert json.loads(r["body"]) == {"logged_out": True, "logout_url": None}
    assert len(r["cookies"]) == 3
    assert len(revoke_calls) == 1


@pytest.mark.parametrize("redirect_uri", ["", "not a url", "/api/v1/auth/callback", "ftp://x/y"])
def test_unusable_redirect_uri_yields_null_logout_url(monkeypatch, revoke_calls, redirect_uri):
    monkeypatch.setattr(lf, "WEBUI_OAUTH_REDIRECT_URI", redirect_uri)
    assert json.loads(lf.lambda_handler(_event(), None)["body"])["logout_url"] is None


def test_revoke_is_attempted_with_token_in_form_body_and_not_logged_or_returned(revoke_calls, caplog):
    caplog.set_level(logging.DEBUG)
    r = lf.lambda_handler(_event(), None)
    assert len(revoke_calls) == 1
    req = revoke_calls[0]
    assert req.full_url == f"{HOSTED}/oauth2/revoke"
    assert req.get_method() == "POST"
    assert req.get_header("Content-type") == "application/x-www-form-urlencoded"
    form = {k: v[0] for k, v in parse_qs(req.data.decode()).items()}
    assert form == {"token": REFRESH_TOKEN, "client_id": lf.COGNITO_CLIENT_ID}
    assert REFRESH_TOKEN not in req.full_url  # the token is only in the POST body
    # The token never reaches the response (body or headers) or the log.
    assert REFRESH_TOKEN not in json.dumps(r)
    assert REFRESH_TOKEN not in caplog.text
    assert "revoked=True" in caplog.text


@pytest.mark.parametrize("failure", [
    urllib.error.URLError("unreachable"),
    urllib.error.HTTPError("u", 400, "bad", {}, None),
    TimeoutError("slow"),
])
def test_revoke_failure_never_fails_the_logout(monkeypatch, caplog, failure):
    def boom(req, timeout=None):
        raise failure

    monkeypatch.setattr(lf.urllib.request, "urlopen", boom)
    caplog.set_level(logging.DEBUG)
    r = lf.lambda_handler(_event(), None)
    assert r["statusCode"] == 200
    assert json.loads(r["body"])["logged_out"] is True
    assert len(r["cookies"]) == 3
    assert REFRESH_TOKEN not in caplog.text
    assert "revoked=False" in caplog.text


def test_no_refresh_cookie_still_clears_without_calling_cognito(revoke_calls):
    r = lf.lambda_handler(_event(cookies=[]), None)
    assert r["statusCode"] == 200
    assert revoke_calls == []
    assert len(r["cookies"]) == 3


def test_refresh_cookie_in_cookie_header_is_revoked_too(revoke_calls):
    ev = _event(cookies=[])
    ev["headers"]["cookie"] = f"a=b; enceladus_refresh_token={REFRESH_TOKEN}"
    lf.lambda_handler(ev, None)
    assert len(revoke_calls) == 1


@pytest.mark.parametrize("kwargs", [
    {"origin": "https://evil.example"},
    {"origin": None},
    {"kit": False},
])
def test_csrf_gate_rejects_without_revoking_or_clearing(revoke_calls, kwargs):
    r = lf.lambda_handler(_event(**kwargs), None)
    assert r["statusCode"] == 403
    assert json.loads(r["body"])["code"] == "AUTH_FORBIDDEN"
    assert "cookies" not in r
    assert revoke_calls == []


def test_get_on_logout_path_is_not_a_logout(revoke_calls):
    r = lf.lambda_handler(_event(method="GET"), None)
    assert r["statusCode"] == 405
    assert revoke_calls == []


def test_route_is_declared_on_the_http_api_and_wired_to_auth_refresh():
    api = (ROOT / "infrastructure" / "cloudformation" / "03-api.yaml").read_text()
    m = re.search(r"  RouteAuthLogout:\n    Type: AWS::ApiGatewayV2::Route\n    Properties:\n(.*?)\n\n", api, re.S)
    assert m, "RouteAuthLogout missing from 03-api.yaml"
    assert "RouteKey: POST /api/v1/auth/logout" in m.group(1)
    assert "Target: !Sub integrations/${AuthRefreshIntegration}" in m.group(1)


def test_no_new_cfn_parameter_or_env_is_needed_for_logout():
    compute = (ROOT / "infrastructure" / "cloudformation" / "02-compute.yaml").read_text()
    assert "COGNITO_LOGOUT_URI" not in compute and "CognitoLogoutUri" not in compute
