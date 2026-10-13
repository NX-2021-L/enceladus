"""DVP-TSK-B24: enceladus passkeys, auth_refresh side.

1. The code default for COGNITO_HOSTED_UI_DOMAIN is the managed-login v2 custom
   domain, and 02-compute declares it explicitly on both planes.
2. The token exchange runs on that domain; on `invalid_grant` it retries ONCE
   on the classic prefix domain (MCP DCR domain), and on nothing else.
3. The callback with no code: `?result=` -> 302 /?passkey_result=<urlencoded>,
   neither -> 302 /, cookies untouched; real failures keep their behaviour.

DVP-TSK-B28: "Add a passkey" runs authorize prompt=login with the fixed
passkey-intent state; after a SUCCESSFUL code exchange (cookies set as usual)
the callback 302s to the custom domain's /passkeys/add. Any other state, and a
failed exchange, behave as before.
"""
import importlib.util
import io
import json
import base64
import pathlib
import sys
import urllib.error
from urllib.parse import parse_qs, urlparse, urlencode

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "shared_layer" / "python"))
sys.path.insert(0, str(HERE.parent / "shared_layer"))
spec = importlib.util.spec_from_file_location("auth_refresh_lf_passkey", HERE / "lambda_function.py")
lf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lf)

ROOT = HERE.parents[2]
CUSTOM = "https://auth.enceladus.jreese.net"
PREFIX = "https://enceladus-status-356364570033.auth.us-east-1.amazoncognito.com"


def _callback(query):
    return lf.lambda_handler(
        {
            "requestContext": {"http": {"method": "GET", "path": "/api/v1/auth/callback"}},
            "queryStringParameters": query,
            "headers": {},
            "cookies": [],
        },
        None,
    )


class _Resp:
    def __init__(self, payload):
        self._b = json.dumps(payload).encode()

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _http_error(url, code, payload):
    return urllib.error.HTTPError(url, code, "err", {}, io.BytesIO(json.dumps(payload).encode()))


def _fake_urlopen(monkeypatch, script):
    """script: {domain: payload-or-(status, payload)}; records the requested URLs."""
    calls = []

    def fake(req, timeout=0):
        calls.append(req.full_url)
        for domain, outcome in script.items():
            if req.full_url == f"{domain}/oauth2/token":
                if isinstance(outcome, tuple):
                    raise _http_error(req.full_url, outcome[0], outcome[1])
                return _Resp(outcome)
        raise AssertionError(f"unexpected token URL {req.full_url}")

    monkeypatch.setattr(lf.urllib.request, "urlopen", fake)
    return calls


# --- 1. domain config -------------------------------------------------------


def test_code_default_is_the_custom_domain():
    assert lf.COGNITO_CUSTOM_DOMAIN == CUSTOM
    assert lf.COGNITO_HOSTED_UI_DOMAIN == CUSTOM
    assert lf.COGNITO_PREFIX_DOMAIN == PREFIX


def test_02_compute_sets_hosted_ui_domain_for_auth_refresh_only_on_the_custom_domain():
    text = (ROOT / "infrastructure/cloudformation/02-compute.yaml").read_text()
    start = text.index("  AuthRefreshFunction:")
    end = text.index("\n  ", text.index("      Tags:", start))
    block = text[start:end]
    assert f"COGNITO_HOSTED_UI_DOMAIN: {CUSTOM}" in block
    # the MCP / DCR classic domain must not be re-pointed by this change
    assert "amazoncognito.com" not in block.split("COGNITO_HOSTED_UI_DOMAIN:")[1].split("Tags:")[0]


# --- 2. token exchange ------------------------------------------------------


def test_exchange_uses_the_custom_domain(monkeypatch):
    calls = _fake_urlopen(monkeypatch, {CUSTOM: {"id_token": "ID", "refresh_token": "RT"}})
    assert lf._exchange_code_for_tokens("c1") == {"id_token": "ID", "refresh_token": "RT"}
    assert calls == [f"{CUSTOM}/oauth2/token"]


def test_invalid_grant_retries_once_on_the_prefix_domain(monkeypatch):
    calls = _fake_urlopen(
        monkeypatch,
        {CUSTOM: (400, {"error": "invalid_grant"}), PREFIX: {"id_token": "ID2", "refresh_token": None}},
    )
    assert lf._exchange_code_for_tokens("c1")["id_token"] == "ID2"
    assert calls == [f"{CUSTOM}/oauth2/token", f"{PREFIX}/oauth2/token"]


def test_invalid_grant_on_both_domains_fails_after_exactly_one_retry(monkeypatch):
    calls = _fake_urlopen(
        monkeypatch,
        {CUSTOM: (400, {"error": "invalid_grant"}), PREFIX: (400, {"error": "invalid_grant"})},
    )
    with pytest.raises(ValueError):
        lf._exchange_code_for_tokens("c1")
    assert len(calls) == 2


@pytest.mark.parametrize("err", ["invalid_client", "invalid_request", "unauthorized_client", ""])
def test_other_errors_do_not_retry(monkeypatch, err):
    calls = _fake_urlopen(monkeypatch, {CUSTOM: (400, {"error": err})})
    with pytest.raises(ValueError):
        lf._exchange_code_for_tokens("c1")
    assert calls == [f"{CUSTOM}/oauth2/token"]


def test_no_retry_when_the_configured_domain_is_already_the_prefix_domain(monkeypatch):
    monkeypatch.setattr(lf, "COGNITO_HOSTED_UI_DOMAIN", PREFIX + "/")
    calls = _fake_urlopen(monkeypatch, {PREFIX: (400, {"error": "invalid_grant"})})
    with pytest.raises(ValueError):
        lf._exchange_code_for_tokens("c1")
    assert calls == [f"{PREFIX}/oauth2/token"]


def test_callback_with_code_still_sets_cookies_and_redirects(monkeypatch):
    _fake_urlopen(monkeypatch, {CUSTOM: {"id_token": "ID", "refresh_token": "RT"}})
    r = _callback({"code": "c1", "state": ""})
    assert r["statusCode"] == 302
    assert r["headers"]["Location"] == "/"
    assert any(c.startswith("enceladus_id_token=ID;") for c in r["cookies"])
    assert any(c.startswith("enceladus_refresh_token=RT;") for c in r["cookies"])


def test_callback_exchange_failure_still_bounces_to_root_without_cookies(monkeypatch):
    _fake_urlopen(monkeypatch, {CUSTOM: (400, {"error": "invalid_client"})})
    r = _callback({"code": "bad"})
    assert r["statusCode"] == 302 and r["headers"]["Location"] == "/"
    assert "cookies" not in r


# --- 3. callback without a code (passkey add return) ------------------------


@pytest.mark.parametrize("result", ["success", "invalid_session", "some_new_value"])
def test_result_without_code_redirects_to_the_app_with_passkey_result(result):
    r = _callback({"result": result})
    assert r["statusCode"] == 302
    assert r["headers"]["Location"] == f"/?passkey_result={result}"
    assert r["headers"]["Cache-Control"] == "no-store"
    assert "cookies" not in r  # session cookies untouched


def test_result_is_urlencoded_and_cannot_inject_a_redirect_target():
    r = _callback({"result": "a&b=c d#x//evil.example"})
    loc = r["headers"]["Location"]
    assert loc.startswith("/?passkey_result=")
    parsed = urlparse(loc)
    assert parsed.path == "/" and not parsed.netloc and not parsed.fragment
    assert parse_qs(parsed.query) == {"passkey_result": ["a&b=c d#x//evil.example"]}


@pytest.mark.parametrize("query", [None, {}, {"result": ""}, {"state": "abc"}])
def test_neither_code_nor_result_redirects_to_root(query):
    r = _callback(query)
    assert r["statusCode"] == 302
    assert r["headers"]["Location"] == "/"
    assert "cookies" not in r


def test_error_param_keeps_its_behaviour_and_wins_over_result():
    r = _callback({"error": "access_denied", "result": "success"})
    assert r["statusCode"] == 302 and r["headers"]["Location"] == "/"


def test_code_takes_priority_over_result(monkeypatch):
    _fake_urlopen(monkeypatch, {CUSTOM: {"id_token": "ID", "refresh_token": None}})
    r = _callback({"code": "c1", "result": "success"})
    assert any(c.startswith("enceladus_id_token=ID;") for c in r["cookies"])


# --- 4. DVP-TSK-B28: passkey-intent state -> /passkeys/add ------------------

MARKER = "/__passkey_add__"
CLIENT = "6q607dk3liirhtecgps7hifmlk"


def _state(path):
    return base64.urlsafe_b64encode(path.encode("utf-8")).decode("ascii").rstrip("=")


def _expected_add_url():
    q = urlencode({"client_id": lf.COGNITO_CLIENT_ID, "redirect_uri": lf.WEBUI_OAUTH_REDIRECT_URI})
    return f"{CUSTOM}/passkeys/add?{q}"


def test_marker_survives_the_state_path_validation_unchanged():
    assert lf.PASSKEY_ADD_STATE_PATH == MARKER
    assert lf._safe_return_path(MARKER) == MARKER
    assert lf._b64url_decode_path(_state(MARKER)) == MARKER


def test_marker_state_with_good_exchange_redirects_to_custom_domain_passkeys_add(monkeypatch):
    _fake_urlopen(monkeypatch, {CUSTOM: {"id_token": "ID", "refresh_token": "RT"}})
    r = _callback({"code": "c1", "state": _state(MARKER)})
    assert r["statusCode"] == 302
    loc = r["headers"]["Location"]
    assert loc == _expected_add_url()
    parsed = urlparse(loc)
    assert f"{parsed.scheme}://{parsed.netloc}" == CUSTOM and parsed.path == "/passkeys/add"
    assert parse_qs(parsed.query) == {
        "client_id": [CLIENT],
        "redirect_uri": [lf.WEBUI_OAUTH_REDIRECT_URI],
    }
    assert r["headers"]["Cache-Control"] == "no-store"
    # cookies set exactly as for a normal login
    assert any(c.startswith("enceladus_id_token=ID;") for c in r["cookies"])
    assert any(c.startswith("enceladus_session_at=") for c in r["cookies"])
    assert any(c.startswith("enceladus_refresh_token=RT;") for c in r["cookies"])


def test_marker_state_after_prefix_domain_fallback_still_goes_to_the_custom_domain(monkeypatch):
    calls = _fake_urlopen(
        monkeypatch,
        {CUSTOM: (400, {"error": "invalid_grant"}), PREFIX: {"id_token": "ID2", "refresh_token": None}},
    )
    r = _callback({"code": "c1", "state": _state(MARKER)})
    assert calls == [f"{CUSTOM}/oauth2/token", f"{PREFIX}/oauth2/token"]
    assert r["headers"]["Location"] == _expected_add_url()
    assert any(c.startswith("enceladus_id_token=ID2;") for c in r["cookies"])


def test_marker_state_never_targets_the_prefix_domain_even_if_it_is_configured(monkeypatch):
    monkeypatch.setattr(lf, "COGNITO_HOSTED_UI_DOMAIN", PREFIX)
    _fake_urlopen(monkeypatch, {PREFIX: {"id_token": "ID", "refresh_token": None}})
    r = _callback({"code": "c1", "state": _state(MARKER)})
    assert r["headers"]["Location"].startswith(f"{CUSTOM}/passkeys/add?")


@pytest.mark.parametrize("path", ["/", "/projects?x=1", "/__passkey_add__/x", "/__passkey_add__?a=1", "/x/__passkey_add__"])
def test_normal_state_keeps_the_existing_redirect(monkeypatch, path):
    _fake_urlopen(monkeypatch, {CUSTOM: {"id_token": "ID", "refresh_token": "RT"}})
    r = _callback({"code": "c1", "state": _state(path)})
    assert r["statusCode"] == 302
    assert r["headers"]["Location"] == path
    assert any(c.startswith("enceladus_id_token=ID;") for c in r["cookies"])


def test_marker_state_with_failed_exchange_takes_the_existing_error_path(monkeypatch):
    _fake_urlopen(monkeypatch, {CUSTOM: (400, {"error": "invalid_client"})})
    r = _callback({"code": "bad", "state": _state(MARKER)})
    assert r["statusCode"] == 302 and r["headers"]["Location"] == "/"
    assert "cookies" not in r


def test_marker_state_with_an_error_param_still_bounces_to_root():
    r = _callback({"error": "access_denied", "state": _state(MARKER)})
    assert r["statusCode"] == 302 and r["headers"]["Location"] == "/"
    assert "cookies" not in r


def test_passkeys_add_return_with_marker_state_but_no_code_is_the_result_redirect():
    r = _callback({"result": "success", "state": _state(MARKER)})
    assert r["headers"]["Location"] == "/?passkey_result=success"
    assert "cookies" not in r
