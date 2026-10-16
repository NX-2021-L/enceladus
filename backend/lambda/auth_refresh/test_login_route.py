"""DVP-TSK-B07: GET /api/v1/auth/login, the step-up re-login entry.

The @io-kit/auth cognitoAdapter navigates to
/api/v1/auth/login?returnTo=<path>&prompt=login&max_age=0. The edge only has to
force a real Cognito re-login and bring the user back through the existing
callback, so the route must 302 to the Hosted-UI authorize endpoint with a
`state` the callback decodes unchanged, and must be declared on the HTTP API.
"""
import importlib.util
import pathlib
import re
import sys
from urllib.parse import parse_qs, urlparse

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "shared_layer" / "python"))
sys.path.insert(0, str(HERE.parent / "shared_layer"))
spec = importlib.util.spec_from_file_location("auth_refresh_lf_login", HERE / "lambda_function.py")
lf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lf)

ROOT = HERE.parents[2]
HOSTED = "https://auth.enceladus.jreese.net"  # DVP-TSK-B24: managed-login v2 custom domain


def _event(query=None, method="GET", path="/api/v1/auth/login"):
    return {
        "requestContext": {"http": {"method": method, "path": path}},
        "queryStringParameters": query,
        "headers": {},
        "cookies": [],
    }


def _login(query=None):
    r = lf.lambda_handler(_event(query), None)
    assert r["statusCode"] == 302
    assert r["headers"]["Cache-Control"] == "no-store"
    loc = urlparse(r["headers"]["Location"])
    return loc, {k: v[0] for k, v in parse_qs(loc.query, keep_blank_values=True).items()}


def _state_for(path):
    import base64
    return base64.urlsafe_b64encode(path.encode()).decode().rstrip("=")


def test_redirects_to_hosted_ui_authorize_with_step_up_params():
    loc, q = _login({"returnTo": "/escalations/ESC-1?tab=gate", "prompt": "login", "max_age": "0"})
    assert f"{loc.scheme}://{loc.netloc}" == HOSTED
    assert loc.path == "/oauth2/authorize"
    assert q["response_type"] == "code"
    assert q["client_id"] == lf.COGNITO_CLIENT_ID
    assert q["redirect_uri"] == lf.WEBUI_OAUTH_REDIRECT_URI
    assert q["scope"] == "openid email profile aws.cognito.signin.user.admin"
    assert q["prompt"] == "login"
    assert q["max_age"] == "0"
    assert set(q) == {"response_type", "client_id", "redirect_uri", "scope", "state", "prompt", "max_age"}


def test_state_round_trips_through_callback_decoder():
    _, q = _login({"returnTo": "/escalations/ESC-1?tab=gate&x=a b"})
    assert "=" not in q["state"]
    assert lf._b64url_decode_path(q["state"]) == "/escalations/ESC-1?tab=gate&x=a b"


def test_state_matches_spa_build_login_url_encoding():
    _, q = _login({"returnTo": "/gates"})
    assert q["state"] == _state_for("/gates")


@pytest.mark.parametrize(
    "return_to",
    [
        "https://evil.example",
        "//evil.example",
        "/\\evil.example",
        "/api/v1/auth/callback",
        "/api/v1/auth/callback?code=x",
        "/api/v1/auth/login?returnTo=/x",
        "javascript:alert(1)",
        "/ok\r\nSet-Cookie: x=1",
        "",
    ],
)
def test_unsafe_return_to_falls_back_to_root(return_to):
    _, q = _login({"returnTo": return_to})
    assert q["state"] == _state_for("/")
    assert lf._b64url_decode_path(q["state"]) == "/"


def test_missing_return_to_and_missing_query_default_to_root():
    for query in (None, {}):
        _, q = _login(query)
        assert q["state"] == _state_for("/")
        assert "prompt" not in q and "max_age" not in q


def test_only_prompt_login_passes_through():
    for value in ("consent", "none", "select_account", "LOGIN", ""):
        _, q = _login({"returnTo": "/", "prompt": value})
        assert "prompt" not in q, value


@pytest.mark.parametrize("value", ["-1", "abc", "", "1.5", "1e3", " 0", "²", "99999999999"])
def test_invalid_max_age_is_dropped(value):
    _, q = _login({"returnTo": "/", "max_age": value})
    assert "max_age" not in q


@pytest.mark.parametrize("value", ["0", "300"])
def test_valid_max_age_passes_through(value):
    _, q = _login({"returnTo": "/", "max_age": value})
    assert q["max_age"] == value


def test_hosted_ui_trailing_slash_is_stripped(monkeypatch):
    monkeypatch.setattr(lf, "COGNITO_HOSTED_UI_DOMAIN", HOSTED + "/")
    r = lf.lambda_handler(_event({"returnTo": "/"}), None)
    assert r["headers"]["Location"].startswith(HOSTED + "/oauth2/authorize?")


def test_login_needs_no_cookie_and_sets_none():
    r = lf.lambda_handler(_event({"returnTo": "/"}), None)
    assert "cookies" not in r


def test_callback_decoder_still_rejects_unsafe_state():
    assert lf._b64url_decode_path(_state_for("//evil.example")) == "/"
    assert lf._b64url_decode_path(_state_for("/api/v1/auth/callback")) == "/"
    assert lf._b64url_decode_path(_state_for("/\\evil.example")) == "/"
    assert lf._b64url_decode_path(_state_for("/escalations/ESC-1")) == "/escalations/ESC-1"
    assert lf._b64url_decode_path("") == "/"
    assert lf._b64url_decode_path("!!!") == "/"


def test_login_route_key_targets_auth_refresh():
    api = (ROOT / "infrastructure/cloudformation/03-api.yaml").read_text()
    m = re.search(r"RouteKey: GET /api/v1/auth/login\n\s+Target: !Sub integrations/\$\{(\w+)\}", api)
    assert m, "GET /api/v1/auth/login route key missing from 03-api.yaml"
    assert m.group(1) == "AuthRefreshIntegration"
    block = api[api.index("  RouteAuthLogin:"):]
    assert "AuthorizerId" not in block.split("\n\n")[0], "login route must stay public"
