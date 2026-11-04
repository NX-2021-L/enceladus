"""Test defaults for the MCP server suite.

ENC-TSK-S29-0A: the per-step governance probe in execute would reach the governance API (network)
for tests that load the real server with fake tool handlers. It is off here; the S29-0A tests
install their own scripted probe on RUNTIME.

ENC-TSK-S44 (incident ENC-ISS-894): the suite must be HERMETIC. server.py defaults every *_API_BASE to
https://enceladus.jreese.net/... and reads the internal API key from the shell, so on a developer host a test that
reached the real transport (the governance_update tests did) wrote to the LIVE governance bundle. This module makes that
impossible by construction:

  1. At conftest import (before any test module loads server.py) every ENCELADUS_*_API_BASE / CHECKOUT_SERVICE_API_BASE /
     *_INTERNAL_API_KEY(S) / key-file / cookie variable is removed from os.environ, and the AWS credential sources are
     neutralised, so freshly loaded server modules compute inert defaults.
  2. An autouse per-test fixture re-points the already-loaded server module copies (several test modules load their own
     copy via importlib) at the unroutable host http://127.0.0.1:9 and blanks their internal keys.
  3. An autouse per-test fixture replaces the network transports (urllib.request.urlopen, http.client HTTP(S)Connection,
     and the botocore wire send) with a guard that raises
     RuntimeError("hermetic test: network call blocked: <url>"). Tests that need a transport patch it themselves
     (unittest.mock / monkeypatch applied inside the test overrides the guard).
"""
import http.client
import os
import re
import sys
import urllib.error
import urllib.request

import pytest

INERT_BASE = "http://127.0.0.1:9"

_ENV_NAME_RE = re.compile(
    r"^(ENCELADUS_[A-Z0-9_]*(API_BASE|API_URL|INTERNAL_API_KEYS?|INTERNAL_KEYS?|API_KEY|COOKIE|KEY_FILE|KEYS_FILE|SECRET_ARN)"
    r"|CHECKOUT_SERVICE_API_BASE"
    r"|[A-Z0-9_]*INTERNAL_API_KEYS?(_PREVIOUS)?"
    r"|ENCELADUS_INTERNAL_[A-Z0-9_]*)$"
)
# Endpoint variables pointed at the unroutable host (NOT merely deleted: deleting them would make server.py fall back to its
# live https://enceladus.jreese.net/... defaults, including for modules a test loads itself after the fixture ran).
_INERT_ENDPOINT_ENV = {
    "ENCELADUS_COORDINATION_API_BASE": INERT_BASE,
    "ENCELADUS_TRACKER_API_BASE": INERT_BASE,
    "ENCELADUS_DOCUMENT_API_BASE": INERT_BASE,
    "ENCELADUS_GOVERNANCE_API_BASE": INERT_BASE,
    "ENCELADUS_PROJECTS_API_BASE": INERT_BASE,
    "CHECKOUT_SERVICE_API_BASE": INERT_BASE,
    "ENCELADUS_DEPLOY_API_BASE": INERT_BASE,
    "ENCELADUS_CHANGELOG_API_BASE": INERT_BASE,
    "ENCELADUS_GITHUB_API_BASE": INERT_BASE,
    "ENCELADUS_GRAPH_QUERY_API_BASE": INERT_BASE,
    "ENCELADUS_HEALTH_API_URL": INERT_BASE,
    "ENCELADUS_CALLBACK_ENDPOINT": INERT_BASE + "/requests/{request_id}/callback",
}
_AWS_ENV_NAMES = (
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
)


def _scrub_environment() -> None:
    for name in list(os.environ):
        if _ENV_NAME_RE.match(name):
            os.environ.pop(name, None)
    for name in _AWS_ENV_NAMES:
        os.environ.pop(name, None)
    # No shared credentials / config file and no IMDS fallback: boto3 can never mint live credentials.
    os.environ.update(_INERT_ENDPOINT_ENV)
    os.environ["AWS_SHARED_CREDENTIALS_FILE"] = os.devnull
    os.environ["AWS_CONFIG_FILE"] = os.devnull
    os.environ["AWS_EC2_METADATA_DISABLED"] = "true"
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")


_scrub_environment()
os.environ.setdefault("ENCELADUS_EXECUTE_GOVERNANCE_PROBE", "off")

# Transport attempts the guard blocked, as (test node id, description); summarised at the end of the run.
_BLOCKED = []
_CURRENT_TEST = {"nodeid": "<collection>"}


_HERE = os.path.dirname(os.path.abspath(__file__))


def _is_server_module(mod) -> bool:
    """True for every loaded copy of a non-test module of this package (server.py is loaded once per test module)."""
    path = getattr(mod, "__file__", None)
    if not path:
        return False
    path = os.path.abspath(str(path))
    base = os.path.basename(path)
    if os.path.dirname(path) != _HERE or base.startswith("test_") or base == "conftest.py":
        return False
    return any(_inert_value(n, v) is not None for n, v in list(vars(mod).items()))


def _server_modules():
    return [m for m in list(sys.modules.values()) if _is_server_module(m)]


def _inert_value(name: str, value):
    """Return the inert replacement for a module global, or None when the global is not endpoint/credential config."""
    if name.endswith("_API_BASE") and isinstance(value, str):
        return INERT_BASE
    if name == "HEALTH_API_URL" and isinstance(value, str):
        return INERT_BASE
    if name == "CALLBACK_ENDPOINT_TEMPLATE" and isinstance(value, str):
        return INERT_BASE + "/requests/{request_id}/callback"
    if name == "DEPLOY_API_COOKIE" and isinstance(value, str):
        return ""
    if "INTERNAL_API_KEY" in name:
        if isinstance(value, str):
            return ""
        if isinstance(value, (tuple, list)):
            return ()
    return None


def _guard_message(target) -> str:
    return f"hermetic test: network call blocked: {target}"


class HermeticNetworkBlocked(RuntimeError, urllib.error.URLError):
    """Raised for every blocked transport attempt.

    It is a RuntimeError (the contract of the guard) AND a URLError/OSError, so code that treats an unreachable
    host as a handled condition (AppConfig flag fallback on localhost:2772, "API unreachable" UPSTREAM_ERROR
    envelopes) keeps its production control flow while nothing ever leaves the process.
    """

    def __init__(self, target):
        urllib.error.URLError.__init__(self, _guard_message(target))
        self.target = target

    def __str__(self) -> str:
        return _guard_message(self.target)


def _record(target) -> None:
    _BLOCKED.append((_CURRENT_TEST["nodeid"], str(target)))


def _blocked_urlopen(url, *args, **kwargs):
    target = getattr(url, "full_url", url)
    _record(target)
    raise HermeticNetworkBlocked(target)


def _blocked_connect(self, *args, **kwargs):
    target = f"{getattr(self, 'host', '?')}:{getattr(self, 'port', '?')}"
    _record(target)
    raise HermeticNetworkBlocked(target)


def _blocked_botocore_send(self, request, *args, **kwargs):
    target = getattr(request, "url", request)
    _record(target)
    raise HermeticNetworkBlocked(target)


@pytest.fixture(autouse=True)
def _hermetic_environment(monkeypatch, request):
    _CURRENT_TEST["nodeid"] = request.node.nodeid

    # (a) environment: no endpoint, key, key-file or AWS credential source can leak into the test process.
    for name in list(os.environ):
        if _ENV_NAME_RE.match(name):
            monkeypatch.delenv(name, raising=False)
    for name in _AWS_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    for name, value in _INERT_ENDPOINT_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", os.devnull)
    monkeypatch.setenv("AWS_CONFIG_FILE", os.devnull)
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")

    # (b) module globals of every loaded server.py copy: inert bases, blank keys.
    for mod in _server_modules():
        for name, value in list(vars(mod).items()):
            inert = _inert_value(name, value)
            if inert is not None:
                monkeypatch.setattr(mod, name, inert, raising=False)

    # (c) transports: any attempt raises. Applied before the test body, so a test's own patch wins.
    monkeypatch.setattr(urllib.request, "urlopen", _blocked_urlopen)
    monkeypatch.setattr(http.client.HTTPConnection, "connect", _blocked_connect)
    monkeypatch.setattr(http.client.HTTPSConnection, "connect", _blocked_connect)
    try:
        from botocore.httpsession import URLLib3Session

        monkeypatch.setattr(URLLib3Session, "send", _blocked_botocore_send)
    except Exception:  # pragma: no cover - botocore not installed
        pass
    yield


def pytest_terminal_summary(terminalreporter):
    if not _BLOCKED:
        terminalreporter.write_line("[hermetic] no network call was attempted by any test")
        return
    terminalreporter.write_sep("-", f"hermetic guard blocked {len(_BLOCKED)} network attempt(s)")
    for nodeid, target in _BLOCKED:
        terminalreporter.write_line(f"  {nodeid} -> {target}")
