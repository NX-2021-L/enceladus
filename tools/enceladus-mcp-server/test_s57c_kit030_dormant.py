"""ENC-TSK-S57-C / S57-E: the io-kit-mcp-edge 0.3.0 edition beside the pinned 0.1.3, selected for gamma only.

The zip carries 0.1.3 at its root (requirements.txt, production) and 0.3.0 under ``_kit030``. A base URL in
``server._KIT030_BASES`` (gamma only since S57-E) runs the 0.3.0 edge; every other base, production included, takes the
unchanged 0.1.3 path.

The 0.3.0 behaviour tests run in a fresh interpreter (a process holds one ``io_kit_mcp_edge``) against a real 0.3.0 kit
named by S57C_KIT030_DIR (the directory that holds ``io_kit_mcp_edge/``, e.g. a ``pip install --no-deps --target``); they skip
cleanly when it is not set. CI does not install the kit, so they are local/pre-activation evidence.
"""
import json
import os
import pathlib
import subprocess
import sys
import textwrap

import pytest

from test_oauth_proxy import _load_server

HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
GAMMA = "https://mcp-gamma.jreese.net"
PROD = "https://mcp.jreese.net"
GAMMA_SIGNIN_CLIENT = "4r6e9pfkccv050akrcu2ihlen4"


def _kit030_dir():
    raw = os.environ.get("S57C_KIT030_DIR", "")
    if not raw or not (pathlib.Path(raw) / "io_kit_mcp_edge" / "__init__.py").exists():
        pytest.skip("S57C_KIT030_DIR does not hold a 0.3.0 io_kit_mcp_edge")
    dists = list(pathlib.Path(raw).glob("io_kit_mcp_edge-0.3.0.dist-info"))
    if not dists:
        pytest.skip("S57C_KIT030_DIR is not an io-kit-mcp-edge 0.3.0 install")
    return raw


# --- activation state: gamma is selected, nothing else is --------------------------------------

def test_allow_list_is_gamma_only_and_gamma_has_a_sign_in_client():
    mod = _load_server(ENCELADUS_MCP_TRANSPORT="streamable_http")
    assert mod._KIT030_BASES == frozenset({GAMMA})
    assert PROD not in mod._KIT030_BASES
    assert mod._KIT030_SIGNIN_CLIENT_IDS == {GAMMA: GAMMA_SIGNIN_CLIENT}


@pytest.mark.parametrize("domain", ["mcp-gamma.jreese.net", GAMMA, GAMMA + "/"])
def test_gamma_domain_is_selected_and_adds_the_sign_in_client(monkeypatch, domain):
    monkeypatch.setenv("CUSTOM_DOMAIN", domain)
    monkeypatch.setattr(sys, "path", list(sys.path))
    mod = _load_server(ENCELADUS_MCP_TRANSPORT="streamable_http", CUSTOM_DOMAIN=domain)
    assert mod._kit030_selected() is True
    assert mod._kit030_extra_client_ids() == [GAMMA_SIGNIN_CLIENT]
    assert sys.path[0] == mod._KIT030_DIR


@pytest.mark.parametrize("domain", ["mcp.jreese.net", PROD, PROD + "/", "mcp-gamma.jreese.net.evil.example",
                                    "https://mcp-beta.jreese.net", "localhost:8080", ""])
def test_production_and_every_other_base_is_never_selected_and_never_touches_sys_path(monkeypatch, domain):
    monkeypatch.setenv("CUSTOM_DOMAIN", domain)
    monkeypatch.setattr(sys, "path", list(sys.path))
    before = list(sys.path)
    mod = _load_server(ENCELADUS_MCP_TRANSPORT="streamable_http", CUSTOM_DOMAIN=domain)
    assert mod._kit030_selected() is False
    assert mod._kit030_extra_client_ids() == []
    mod._ensure_kit030_path()
    assert sys.path == before


def test_unset_custom_domain_is_never_selected(monkeypatch):
    monkeypatch.delenv("CUSTOM_DOMAIN", raising=False)
    mod = _load_server(ENCELADUS_MCP_TRANSPORT="streamable_http")
    monkeypatch.delenv("CUSTOM_DOMAIN", raising=False)
    assert mod._kit030_selected() is False and mod._kit030_extra_client_ids() == []


def test_selection_follows_custom_domain_exactly_as_the_server_base_does(monkeypatch):
    mod = _load_server(ENCELADUS_MCP_TRANSPORT="streamable_http")
    monkeypatch.setattr(mod, "_KIT030_BASES", frozenset({GAMMA}))
    monkeypatch.setenv("CUSTOM_DOMAIN", "mcp-gamma.jreese.net/")
    assert mod._kit030_env_base() == GAMMA == mod._get_server_base_url({})
    assert mod._kit030_selected() is True
    monkeypatch.setenv("CUSTOM_DOMAIN", PROD)
    assert mod._kit030_selected() is False  # production is not in the list
    monkeypatch.delenv("CUSTOM_DOMAIN")
    assert mod._kit030_selected() is False  # no env, no decision: the 0.1.3 path


def test_path_is_set_only_for_an_allow_listed_base(monkeypatch, tmp_path):
    mod = _load_server(ENCELADUS_MCP_TRANSPORT="streamable_http")
    monkeypatch.setattr(mod, "_KIT030_BASES", frozenset({GAMMA}))
    monkeypatch.setattr(mod, "_KIT030_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.setenv("CUSTOM_DOMAIN", PROD)
    mod._ensure_kit030_path()
    assert str(tmp_path) not in sys.path
    monkeypatch.setenv("CUSTOM_DOMAIN", GAMMA)
    mod._ensure_kit030_path()
    mod._ensure_kit030_path()  # idempotent
    assert sys.path[0] == str(tmp_path) and sys.path.count(str(tmp_path)) == 1


def test_legacy_verifier_accepts_the_sign_in_client_only_in_030_mode(monkeypatch):
    jwt = pytest.importorskip("jwt")
    rsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")
    import time
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    mod = _load_server(ENCELADUS_MCP_TRANSPORT="streamable_http")
    monkeypatch.setattr(mod, "_get_cognito_jwks", lambda: {"k1": key.public_key()})
    issuer = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TestPool"

    def mint(client):
        return jwt.encode({"iss": issuer, "sub": "u", "token_use": "access", "client_id": client,
                           "exp": int(time.time()) + 300}, key, algorithm="RS256", headers={"kid": "k1"})

    assert mod._verify_cognito_jwt(mint("test-client-id"))["sub"] == "u"
    with pytest.raises(ValueError, match="client_id mismatch"):
        mod._verify_cognito_jwt(mint(GAMMA_SIGNIN_CLIENT))  # prod / unselected: unchanged
    monkeypatch.setattr(mod, "_KIT030_BASES", frozenset({GAMMA}))
    monkeypatch.setenv("CUSTOM_DOMAIN", GAMMA)
    assert mod._verify_cognito_jwt(mint(GAMMA_SIGNIN_CLIENT))["sub"] == "u"
    assert mod._verify_cognito_jwt(mint("test-client-id"))["sub"] == "u"
    with pytest.raises(ValueError, match="client_id mismatch"):
        mod._verify_cognito_jwt(mint("someone-else"))


# --- 0.3.0 behaviour, fresh interpreter with the real kit ---------------------------------------

_CHILD = textwrap.dedent('''
    import json, os, sys
    sys.path.insert(0, os.getcwd())
    import test_oauth_proxy as t
    kit030, base, mode = sys.argv[1], sys.argv[2], sys.argv[3]
    mod = t._load_server(ENCELADUS_MCP_TRANSPORT="streamable_http")
    os.environ["CUSTOM_DOMAIN"] = base
    mod._KIT030_BASES = frozenset({"https://mcp-gamma.jreese.net"})
    mod._KIT030_DIR = kit030
    out = {"kit_before": "io_kit_mcp_edge" in sys.modules}
    mod._ensure_kit030_path()
    calls = []
    mod._handle_cognito_authorize = lambda e: calls.append("authorize") or {"statusCode": 299, "headers": {}, "body": ""}
    mod._handle_cognito_callback = lambda e: calls.append("callback") or {"statusCode": 299, "headers": {}, "body": ""}
    mod._handle_cognito_token = lambda e: calls.append("token") or {"statusCode": 298, "headers": {}, "body": "tok"}
    mod._handle_cognito_register = lambda e: calls.append("oauth_register") or {"statusCode": 298, "headers": {}, "body": "reg"}
    def ev(path, method="GET", body=""):
        host = base.split("//")[1]
        return {"version": "2.0", "rawPath": path, "rawQueryString": "", "queryStringParameters": {}, "body": body,
                "isBase64Encoded": False, "headers": {"host": host, "x-forwarded-proto": "https"},
                "requestContext": {"http": {"method": method, "path": path, "sourceIp": "1.2.3.4"}}}
    def call(path, method="GET"):
        r = mod.lambda_handler(ev(path, method), None)
        return {"status": r["statusCode"], "headers": r.get("headers", {}), "body": r.get("body", "")}
    res = {}
    for p in ("/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"):
        res["prm" + p] = call(p)
    res["mcp"] = call("/mcp", "POST")
    for p in ("/register", "/authorize", "/callback", "/.well-known/oauth-authorization-server"):
        method = "POST" if p == "/register" else "GET"
        res[p] = call(p, method)
    res["token"] = call("/oauth/token", "POST")
    res["oauth_register"] = call("/oauth/register", "POST")
    k = sys.modules.get("io_kit_mcp_edge")
    out.update(res=res, calls=calls, kit_file=getattr(k, "__file__", None), kit_version=__import__("importlib.metadata").metadata.version("io-kit-mcp-edge") if k else None,
               cfg=sorted(c.__class__.__name__ for c, _ in mod._KIT_EDGES.values()),
               client_ids=[getattr(c, "client_ids", None) for c, _ in mod._KIT_EDGES.values()],
               client_id=[c.client_id for c, _ in mod._KIT_EDGES.values()],
               sign_in=[getattr(c, "sign_in_service", None) for c, _ in mod._KIT_EDGES.values()],
               path0=sys.path[0], import_failed=mod._KIT_IMPORT_FAILED, kit_edges=len(mod._KIT_EDGES))
    print("S57C_JSON " + json.dumps(out))
''')


def _run_child(kit030, base):
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(REPO_ROOT / "backend/lambda/shared_layer/python"), str(HERE)])
    proc = subprocess.run([sys.executable, "-c", _CHILD, kit030, base, "x"], cwd=HERE, env=env,
                          capture_output=True, text=True, timeout=180)
    line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("S57C_JSON ")), None)
    assert line, f"child failed rc={proc.returncode}\n{proc.stderr[-2000:]}"
    return json.loads(line[len("S57C_JSON "):])


@pytest.fixture(scope="module")
def gamma_run():
    return _run_child(_kit030_dir(), GAMMA)


def test_gamma_loads_030_from_the_kit030_dir_before_any_kit_import(gamma_run):
    assert gamma_run["kit_before"] is False
    assert gamma_run["path0"] == os.environ["S57C_KIT030_DIR"]
    assert gamma_run["kit_version"] == "0.3.0"
    assert gamma_run["kit_file"].startswith(os.environ["S57C_KIT030_DIR"])
    assert gamma_run["import_failed"] is False and gamma_run["kit_edges"] == 1


def test_gamma_edge_config_is_the_explicit_sign_in_form(gamma_run):
    assert gamma_run["sign_in"] == [GAMMA]
    assert gamma_run["client_id"] == [GAMMA_SIGNIN_CLIENT]
    assert gamma_run["client_ids"] == [[GAMMA_SIGNIN_CLIENT, "test-client-id"]]


@pytest.mark.parametrize("path", ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"])
def test_gamma_prm_names_the_base_and_carries_the_version_header(gamma_run, path):
    r = gamma_run["res"]["prm" + path]
    assert r["status"] == 200
    assert r["headers"]["x-io-kit-mcp"] == "0.3.0"
    body = json.loads(r["body"])
    assert body["resource"] == GAMMA
    assert body["authorization_servers"] == [GAMMA]


def test_gamma_tokenless_post_is_401_with_a_challenge(gamma_run):
    r = gamma_run["res"]["mcp"]
    assert r["status"] == 401
    assert r["headers"]["www-authenticate"].startswith("Bearer ")
    assert f'resource_metadata="{GAMMA}/.well-known/oauth-protected-resource"' in r["headers"]["www-authenticate"]
    assert r["headers"]["x-io-kit-mcp"] == "0.3.0"


@pytest.mark.parametrize("path", ["/register", "/authorize", "/callback", "/.well-known/oauth-authorization-server"])
def test_gamma_host_no_longer_serves_the_sign_in_service_routes(gamma_run, path):
    assert gamma_run["res"][path]["status"] == 401  # falls to the bearer gate; CloudFront sends these to the sign-in service
    assert "authorize" not in gamma_run["calls"] and "callback" not in gamma_run["calls"]


def test_gamma_host_still_serves_oauth_token_and_oauth_register(gamma_run):
    assert gamma_run["res"]["token"]["status"] == 298 and gamma_run["res"]["oauth_register"]["status"] == 298
    assert gamma_run["calls"] == ["token", "oauth_register"]


def test_production_base_in_the_same_layout_takes_the_013_path():
    kit030 = _kit030_dir()
    run = _run_child(kit030, PROD)
    assert run["path0"] != kit030  # _kit030 never put on sys.path for a base outside the allow-list
    assert "authorize" in run["calls"] and "callback" in run["calls"]  # host legs unchanged
    if run["kit_edges"] == 0:
        pytest.skip("io-kit-mcp-edge 0.1.3 is not installed in this interpreter; legacy gate ran")
    assert run["kit_version"] == "0.1.3"
    assert run["res"]["/register"]["status"] != 401  # the 0.1.3 kit serves /register itself
    assert json.loads(run["res"]["prm/.well-known/oauth-protected-resource"]["body"])["authorization_servers"] == [PROD]
    assert "x-io-kit-mcp" not in run["res"]["prm/.well-known/oauth-protected-resource"]["headers"]


# --- build wiring ----------------------------------------------------------------------------------

def test_requirements_stay_on_013_and_only_workflows_name_030():
    for fn in ("mcp_code", "mcp_streamable"):
        path = REPO_ROOT / "backend" / "lambda" / fn / "requirements.txt"
        if path.exists():
            text = path.read_text()
            assert "io-kit-mcp-edge==0.1.3" in text and "0.3.0" not in text


@pytest.mark.parametrize("rel", [".github/workflows/_build.yml", ".github/workflows/build-lambda-artifacts.yml"])
def test_every_mcp_packaging_site_installs_030_into_kit030_without_deps(rel):
    text = (REPO_ROOT / rel).read_text()
    assert text.count("io-kit-mcp-edge==0.3.0") >= 1
    for chunk in text.split("io-kit-mcp-edge==0.3.0")[:-1]:
        assert "--no-deps" in chunk[-400:] and "_kit030" in chunk[-400:]
    import re
    pins = set(re.findall(r"io-kit-mcp-edge==([0-9.]+)", text))
    assert pins == {"0.3.0"}  # 0.1.3 reaches the zip through requirements.txt only
