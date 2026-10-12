"""ENC-TSK-Q70 (DVP-PLN-016 W4, E16-R14): the MCP server adopts io_kit_mcp_edge in Cognito mode.

The kit edge serves PRM, ASM, POST /register, OPTIONS, the 401 challenge and the bearer
gate; the host keeps /authorize, /callback, /oauth/token and /oauth/register. When the kit
cannot be imported (the other three Lambdas that package server.py never carry it) the
original gate runs unchanged. Non-Cognito (MCP_API_KEY) mode never touches the kit.
"""
import base64
import json
import logging
import time
import urllib.parse

import pytest

jwt = pytest.importorskip("jwt")
rsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")

from test_oauth_proxy import _load_server  # noqa: E402

BASE = "https://mcp.jreese.net"
POOL = "us-east-1_TestPool"
CLIENT = "test-client-id"
ISSUER = f"https://cognito-idp.us-east-1.amazonaws.com/{POOL}"
KID = "q70-key"
COGNITO_DOMAIN = "https://auth.example.com"
OK_BODY = {"jsonrpc": "2.0", "id": 1, "result": {"reached": "mcp-handler"}}


def _b64u(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@pytest.fixture(scope="module")
def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nums = key.public_key().public_numbers()
    jwks = {"keys": [{"kty": "RSA", "kid": KID, "use": "sig", "alg": "RS256", "n": _b64u(nums.n), "e": _b64u(nums.e)}]}
    return key, jwks


def _mint(key, token_use="access", **overrides):
    claims = {"iss": ISSUER, "sub": "user-1", "token_use": token_use, "iat": int(time.time()),
              "exp": int(time.time()) + 600, "cognito:groups": ["admins"]}
    if token_use == "access":
        claims["client_id"] = CLIENT
    else:
        claims["aud"] = CLIENT
    claims.update(overrides)
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": KID})


def _event(path="/mcp", method="POST", token=None, qs=None, body="", host="mcp.jreese.net", extra_headers=None):
    headers = {"host": host, "x-forwarded-proto": "https"}
    if token:
        headers["authorization"] = f"Bearer {token}"
    headers.update(extra_headers or {})
    return {
        "version": "2.0",
        "rawPath": path,
        "rawQueryString": urllib.parse.urlencode(qs or {}),
        "queryStringParameters": qs or {},
        "body": body,
        "isBase64Encoded": False,
        "headers": headers,
        "requestContext": {"http": {"method": method, "path": path, "sourceIp": "1.2.3.4"}},
    }


def _server(**env):
    return _load_server(ENCELADUS_MCP_TRANSPORT="streamable_http", **env)


@pytest.fixture()
def server(keypair, monkeypatch):
    """A Cognito-mode server whose kit edge reads the injected JWKS and whose MCP body is stubbed."""
    pytest.importorskip("io_kit_mcp_edge")
    _, jwks = keypair
    mod = _server()
    seen = []

    async def _stub(event):
        seen.append(event)
        return {"statusCode": 200, "headers": {"content-type": "application/json"},
                "body": json.dumps(OK_BODY), "isBase64Encoded": False}

    monkeypatch.setattr(mod, "_handle_mcp_request", _stub)
    config, _edge = mod._get_kit_edge(BASE)
    config.fetch_jwks = lambda uri: jwks
    mod._q70_seen = seen
    return mod


def _call(mod, event):
    return mod.lambda_handler(event, None)


def _json(res):
    return json.loads(res["body"])


# --- discovery ---------------------------------------------------------------------------

def test_prm_resource_is_the_base_url_on_both_paths(server):
    for path in ("/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"):
        res = _call(server, _event(path=path, method="GET"))
        assert res["statusCode"] == 200
        body = _json(res)
        assert body["resource"] == BASE
        assert body["authorization_servers"] == [BASE]


def test_asm_points_at_the_host_legs_and_the_kit_register(server):
    res = _call(server, _event(path="/.well-known/oauth-authorization-server", method="GET"))
    assert res["statusCode"] == 200
    asm = _json(res)
    assert asm["issuer"] == BASE
    assert asm["authorization_endpoint"] == f"{BASE}/authorize"
    assert asm["token_endpoint"] == f"{BASE}/oauth/token"
    assert asm["registration_endpoint"] == f"{BASE}/register"
    assert asm["revocation_endpoint"] == f"{COGNITO_DOMAIN}/oauth2/revoke"
    assert asm["userinfo_endpoint"] == f"{COGNITO_DOMAIN}/oauth2/userInfo"
    assert asm["jwks_uri"] == f"{ISSUER}/.well-known/jwks.json"
    assert asm["token_endpoint_auth_methods_supported"] == ["none"]
    assert asm["code_challenge_methods_supported"] == ["S256"]


def test_suffixed_asm_path_is_the_bare_document(server):
    bare = _call(server, _event(path="/.well-known/oauth-authorization-server", method="GET"))
    suffixed = _call(server, _event(path="/.well-known/oauth-authorization-server/mcp", method="GET"))
    assert suffixed["statusCode"] == 200
    assert suffixed["body"] == bare["body"]


# --- challenge and registration ----------------------------------------------------------

def test_anonymous_mcp_post_is_a_bearer_challenge(server):
    res = _call(server, _event(body="{}"))
    assert res["statusCode"] == 401
    challenge = res["headers"]["www-authenticate"]
    assert challenge.startswith("Bearer ")
    assert f'resource_metadata="{BASE}/.well-known/oauth-protected-resource"' in challenge
    assert server._q70_seen == []


def test_register_hands_out_the_public_client_and_never_a_secret(server):
    uris = ["https://claude.ai/api/mcp/auth_callback", "http://localhost:4567/cb"]
    res = _call(server, _event(path="/register", body=json.dumps({"redirect_uris": uris, "client_name": "claude"})))
    assert res["statusCode"] == 201
    body = _json(res)
    assert body["client_id"] == CLIENT
    assert body["redirect_uris"] == uris
    assert body["token_endpoint_auth_method"] == "none"
    assert "client_secret" not in res["body"]
    assert "test-client-secret" not in res["body"]


def test_legacy_oauth_register_alias_still_answers_200(server):
    uris = ["http://localhost:9/cb"]
    res = _call(server, _event(path="/oauth/register", body=json.dumps({"redirect_uris": uris})))
    assert res["statusCode"] == 200
    body = _json(res)
    assert body["client_id"] == CLIENT
    assert body["redirect_uris"] == uris
    assert "client_secret" not in res["body"]


# --- host-owned legs stay on the host ----------------------------------------------------

def test_authorize_still_302s_to_cognito_without_resource(server):
    qs = {"response_type": "code", "client_id": CLIENT, "redirect_uri": "http://localhost:9999/cb",
          "state": "abc", "code_challenge": "chal", "code_challenge_method": "S256",
          "resource": f"{BASE}/"}
    res = _call(server, _event(path="/authorize", method="GET", qs=qs))
    assert res["statusCode"] == 302
    location = res["headers"]["location"]
    assert location.startswith(f"{COGNITO_DOMAIN}/oauth2/authorize?")
    params = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
    assert "resource" not in params
    assert params["redirect_uri"] == [f"{BASE}/callback"]
    assert params["client_id"] == [CLIENT]


def test_callback_still_relays_the_code(server):
    relay = base64.urlsafe_b64encode(json.dumps({"ru": "http://localhost:9999/cb", "st": "s1"}).encode()).decode().rstrip("=")
    res = _call(server, _event(path="/callback", method="GET", qs={"code": "abc", "state": relay}))
    assert res["statusCode"] == 302
    assert res["headers"]["location"] == "http://localhost:9999/cb?code=abc&state=s1"


def test_oauth_token_without_grant_type_is_the_host_400(server):
    res = _call(server, _event(path="/oauth/token", body="client_id=x"))
    assert res["statusCode"] == 400
    assert _json(res)["error"] == "invalid_request"


# --- the bearer gate ---------------------------------------------------------------------

def test_valid_access_token_reaches_the_mcp_handler(server, keypair):
    key, _ = keypair
    res = _call(server, _event(token=_mint(key), body='{"jsonrpc":"2.0","id":1,"method":"ping"}'))
    assert res["statusCode"] == 200
    assert _json(res) == OK_BODY
    assert len(server._q70_seen) == 1
    principal = server._q70_seen[0]["io_kit_mcp"]["principal"]
    assert principal["sub"] == "user-1"
    assert principal["groups"] == ["admins"]


def test_access_token_for_another_client_is_401(server, keypair):
    key, _ = keypair
    res = _call(server, _event(token=_mint(key, client_id="someone-else"), body="{}"))
    assert res["statusCode"] == 401
    assert 'error="invalid_token"' in res["headers"]["www-authenticate"]
    assert server._q70_seen == []


def test_id_token_with_the_client_audience_passes(server, keypair):
    key, _ = keypair
    res = _call(server, _event(token=_mint(key, token_use="id"), body="{}"))
    assert res["statusCode"] == 200
    assert len(server._q70_seen) == 1


def test_id_token_with_another_audience_is_401(server, keypair):
    key, _ = keypair
    res = _call(server, _event(token=_mint(key, token_use="id", aud="someone-else"), body="{}"))
    assert res["statusCode"] == 401
    assert server._q70_seen == []


def test_expired_or_foreign_issuer_token_is_401(server, keypair):
    key, _ = keypair
    assert _call(server, _event(token=_mint(key, exp=int(time.time()) - 5), body="{}"))["statusCode"] == 401
    assert _call(server, _event(token=_mint(key, iss="https://evil.example.com/x"), body="{}"))["statusCode"] == 401
    assert server._q70_seen == []


def test_static_mcp_api_key_is_still_refused_in_cognito_mode(keypair, monkeypatch):
    pytest.importorskip("io_kit_mcp_edge")
    mod = _server(ENCELADUS_MCP_API_KEY="static-key")
    res = _call(mod, _event(token="static-key", body="{}"))
    assert res["statusCode"] == 401
    # ... and the same through the legacy gate when the kit is unavailable
    monkeypatch.setitem(__import__("sys").modules, "io_kit_mcp_edge", None)
    legacy = _server(ENCELADUS_MCP_API_KEY="static-key")
    assert _call(legacy, _event(token="static-key", body="{}"))["statusCode"] == 401


def test_no_browser_cors_on_mcp_responses(server, keypair):
    """F5: no browser calls the MCP endpoint (the PWA's /api/v1/coordination/mcp is another Lambda), and
    the server never sent Access-Control-* on MCP responses, so the kit's token-leg-only CORS loses nothing."""
    key, _ = keypair
    res = _call(server, _event(token=_mint(key), body="{}", extra_headers={"origin": "https://claude.ai"}))
    assert res["statusCode"] == 200
    assert not [h for h in res["headers"] if h.lower().startswith("access-control-")]
    pre = _call(server, _event(method="OPTIONS", extra_headers={"origin": "https://claude.ai"}))
    assert pre["statusCode"] == 204
    assert not [h for h in pre["headers"] if h.lower().startswith("access-control-")]


# --- caching and fallback ----------------------------------------------------------------

def test_edge_is_cached_per_base_url(server):
    first = server._get_kit_edge(BASE)
    assert server._get_kit_edge(BASE) is first
    other = server._get_kit_edge("https://mcp-gamma.jreese.net")
    assert other is not first
    assert other[0].resource == "https://mcp-gamma.jreese.net"
    assert other[0].authorization_server["authorization_endpoint"] == "https://mcp-gamma.jreese.net/authorize"


def test_custom_domain_sets_the_base_behind_cloudfront(server, monkeypatch):
    """enceladus-mcp-code sets CUSTOM_DOMAIN; the Function URL host is the origin, not the public name."""
    monkeypatch.setenv("CUSTOM_DOMAIN", "mcp-gamma.jreese.net")
    res = _call(server, _event(path="/.well-known/oauth-protected-resource", method="GET",
                               host="abc123.lambda-url.us-west-2.on.aws"))
    assert _json(res)["resource"] == "https://mcp-gamma.jreese.net"
    asm = _json(_call(server, _event(path="/.well-known/oauth-authorization-server", method="GET",
                                     host="abc123.lambda-url.us-west-2.on.aws")))
    assert asm["registration_endpoint"] == "https://mcp-gamma.jreese.net/register"


def test_each_host_serves_its_own_resource(server):
    res = _call(server, _event(path="/.well-known/oauth-protected-resource", method="GET", host="mcp-gamma.jreese.net"))
    assert _json(res)["resource"] == "https://mcp-gamma.jreese.net"


def test_kit_import_failure_falls_back_to_the_legacy_gate(monkeypatch, caplog):
    monkeypatch.setitem(__import__("sys").modules, "io_kit_mcp_edge", None)  # `import io_kit_mcp_edge` raises
    mod = _server()
    with caplog.at_level(logging.ERROR):
        anon = _call(mod, _event(body="{}"))
        again = _call(mod, _event(body="{}"))
    assert mod._get_kit_edge_api() is None
    for res in (anon, again):
        assert res["statusCode"] == 401
        assert _json(res) == {"error": "Unauthorized", "error_description": "Bearer token required"}
        assert f'resource_metadata="{BASE}/.well-known/oauth-protected-resource"' in res["headers"]["www-authenticate"]
    assert len([r for r in caplog.records if "io_kit_mcp_edge unavailable" in r.getMessage()]) == 1
    # the host PRM and the host legs keep working without the kit
    prm = _call(mod, _event(path="/.well-known/oauth-protected-resource", method="GET"))
    assert prm["statusCode"] == 200 and _json(prm)["resource"] == BASE
    auth = _call(mod, _event(path="/authorize", method="GET", qs={"response_type": "code", "client_id": CLIENT}))
    assert auth["statusCode"] == 302


def test_kit_import_failure_still_validates_a_cognito_jwt(keypair, monkeypatch):
    key, jwks = keypair
    monkeypatch.setitem(__import__("sys").modules, "io_kit_mcp_edge", None)
    mod = _server()
    monkeypatch.setattr(mod, "_get_cognito_jwks", lambda: {k["kid"]: jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(k)) for k in jwks["keys"]})
    seen = []

    async def _stub(event):
        seen.append(event)
        return {"statusCode": 200, "headers": {}, "body": "{}", "isBase64Encoded": False}

    monkeypatch.setattr(mod, "_handle_mcp_request", _stub)
    assert _call(mod, _event(token=_mint(key), body="{}"))["statusCode"] == 200
    assert _call(mod, _event(token=_mint(key, client_id="other"), body="{}"))["statusCode"] == 401
    assert len(seen) == 1


def test_non_cognito_mode_never_loads_the_kit(monkeypatch):
    mod = _server(ENCELADUS_COGNITO_USER_POOL_ID="", ENCELADUS_COGNITO_CLIENT_ID="",
                  ENCELADUS_COGNITO_DOMAIN="", ENCELADUS_MCP_API_KEY="static-key")
    assert not mod._cognito_mode_active()
    monkeypatch.setattr(mod, "_get_kit_edge_api", lambda: pytest.fail("kit consulted outside Cognito mode"))
    bad = _call(mod, _event(token="wrong", body="{}"))
    assert bad["statusCode"] == 401
    assert _json(bad) == {"error": "Unauthorized"}
    prm = _call(mod, _event(path="/.well-known/oauth-protected-resource", method="GET"))
    assert prm["statusCode"] == 200
    assert prm["headers"]["cache-control"] == "public, max-age=3600"  # the host document, not the kit's no-store


def test_the_real_mcp_path_runs_behind_the_edge(keypair):
    """No stub: the post-auth ASGI path (session manager) answers a JSON-RPC initialize behind the kit gate."""
    pytest.importorskip("io_kit_mcp_edge")
    key, jwks = keypair
    mod = _server()
    config, _ = mod._get_kit_edge(BASE)
    config.fetch_jwks = lambda uri: jwks
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                                  "clientInfo": {"name": "q70", "version": "1"}}})
    event = _event(token=_mint(key), body=body, extra_headers={
        "content-type": "application/json", "accept": "application/json, text/event-stream"})
    res = _call(mod, event)
    assert res["statusCode"] == 200
    assert "protocolVersion" in res["body"]


# --- build wiring: prod must run the edge path, not the silent fallback -------------------

REPO_ROOT = __import__("pathlib").Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("function", ["mcp_code", "mcp_streamable"])
def test_function_requirements_pin_the_kit(function):
    """mcp.jreese.net is served by enceladus-mcp-code (live alias) and mcp-gamma by enceladus-mcp-code-gamma, both built
    from backend/lambda/mcp_code. Without the kit in that zip the lazy import fails and the legacy gate runs silently."""
    path = REPO_ROOT / "backend" / "lambda" / function / "requirements.txt"
    if not path.exists():
        pytest.skip(f"{path} not in this checkout")
    lines = [ln.strip() for ln in path.read_text().splitlines()]
    assert "io-kit-mcp-edge==0.1.3" in lines


def test_mcp_code_build_job_mints_the_codeartifact_index_before_the_build_role():
    workflow = REPO_ROOT / ".github" / "workflows" / "_build.yml"
    if not workflow.exists():
        pytest.skip("workflow not in this checkout")
    text = workflow.read_text()
    job = text[text.index("  build-mcp-code:"):]
    read_role = job.index("role/io-kit-github-read")
    mint = job.index("aws codeartifact get-authorization-token")
    build_role = job.index("role/GitHubActions-Build-Role")
    install = job.index("backend/lambda/mcp_code/requirements.txt")
    assert read_role < mint < build_role < install
    assert "::add-mask::" in job[mint:build_role]
    assert "PIP_EXTRA_INDEX_URL=" in job[mint:build_role]
    assert "--only-binary=:all:" in job[install - 400:install + 100]
