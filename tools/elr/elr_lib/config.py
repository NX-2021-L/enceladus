"""ELR profile / configuration resolution.

ELR (Enceladus Local Runner) is an ALTERNATE CLIENT for the governed
Enceladus HTTP APIs -- it is not a bypass. Governance is enforced at the
API boundary (the Lambda handlers); this module only resolves *where*
to send bytes and *which* credential header/token to attach.

Two profiles are supported:

  - "internal"  (default): talks directly to the governed HTTP APIs the
    same way tools/enceladus-mcp-server/server.py does -- base URLs and
    the ``X-Coordination-Internal-Key`` header, resolved from the same
    env var names server.py reads (with the same defaults).
  - "mcp-http": talks to the streaming MCP-over-HTTP gateway
    (tools/enceladus-mcp-server/install_profile.sh /
    backend/lambda/coordination_api/handlers.py:_handle_mcp_http) using
    JSON-RPC 2.0, with an optional bearer token.

Nothing in this module ever prints, logs, or otherwise exposes a secret
value. ``repr()`` of every config object reports only whether a
credential is *configured*, never its contents.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import profiles as elr_profiles

PROFILE_INTERNAL = "internal"
PROFILE_MCP_HTTP = "mcp-http"
VALID_PROFILES = (PROFILE_INTERNAL, PROFILE_MCP_HTTP)

# --- Internal-key profile: base URLs -----------------------------------
# (env var name, default) pairs, mirrored verbatim from
# tools/enceladus-mcp-server/server.py's module-level constants.
_API_BASE_DEFAULTS: Dict[str, Tuple[str, str]] = {
    "coordination": ("ENCELADUS_COORDINATION_API_BASE", "https://jreese.net/api/v1/coordination"),
    "document": ("ENCELADUS_DOCUMENT_API_BASE", "https://jreese.net/api/v1/documents"),
    "deploy": ("ENCELADUS_DEPLOY_API_BASE", "https://jreese.net/api/v1/deploy"),
    "changelog": ("ENCELADUS_CHANGELOG_API_BASE", "https://jreese.net/api/v1/changelog"),
    "tracker": ("ENCELADUS_TRACKER_API_BASE", "https://jreese.net/api/v1/tracker"),
    "checkout": ("CHECKOUT_SERVICE_API_BASE", "https://jreese.net/api/v1/checkout"),
    "governance": ("ENCELADUS_GOVERNANCE_API_BASE", "https://jreese.net/api/v1/governance"),
    "projects": ("ENCELADUS_PROJECTS_API_BASE", "https://jreese.net/api/v1/coordination/projects"),
    "graph_query": (
        "ENCELADUS_GRAPH_QUERY_API_BASE",
        "https://8nkzqkmxqc.execute-api.us-west-2.amazonaws.com/api/v1/tracker/graphsearch",
    ),
    "health": ("ENCELADUS_HEALTH_API_URL", "https://jreese.net/api/v1/health"),
    "github": ("ENCELADUS_GITHUB_API_BASE", "https://jreese.net/api/v1/github"),
}

# Per-API dedicated internal-key env vars. ``checkout`` deliberately reuses
# the tracker key chain (server.py:_checkout_api_request); ``changelog``,
# ``graph_query`` and ``health`` have no dedicated key in server.py and
# fall through to the common chain (health never sends a key at all).
_DEDICATED_KEY_ENV: Dict[str, Optional[str]] = {
    "coordination": "ENCELADUS_COORDINATION_API_INTERNAL_API_KEY",
    "tracker": "ENCELADUS_TRACKER_API_INTERNAL_API_KEY",
    "checkout": "ENCELADUS_TRACKER_API_INTERNAL_API_KEY",
    "document": "ENCELADUS_DOCUMENT_API_INTERNAL_API_KEY",
    "deploy": "ENCELADUS_DEPLOY_API_INTERNAL_API_KEY",
    "governance": "ENCELADUS_GOVERNANCE_API_INTERNAL_API_KEY",
    "projects": "ENCELADUS_PROJECTS_API_INTERNAL_API_KEY",
    "github": "ENCELADUS_GITHUB_API_INTERNAL_API_KEY",
    "changelog": None,
    "graph_query": None,
    "health": None,
}

# Common internal-key fallback chain, in priority order (matches
# server.py's ``_first_nonempty_env`` call building COMMON_INTERNAL_API_KEY).
#
# ENC-TSK-P75 / FR-B4-4..7: ``ENCELADUS_INTERNAL_API_KEY`` is appended LAST
# (lowest priority) -- it is the name elr_lib.identity's posture chain
# (AC-1) uses for its "internal-key" posture, but every EXISTING name here
# still wins when both are set, so this is purely additive: nothing that
# already resolved a key via one of the names above changes which value it
# gets.
COMMON_INTERNAL_KEY_ENV_CHAIN = (
    "ENCELADUS_COORDINATION_API_INTERNAL_API_KEY",
    "ENCELADUS_COORDINATION_INTERNAL_API_KEY",
    "COORDINATION_INTERNAL_API_KEY",
    "COORDINATION_INTERNAL_API_KEY_PREVIOUS",
    "ENCELADUS_INTERNAL_API_KEY",
)

# Auth header name, verbatim from server.py.
INTERNAL_AUTH_HEADER = "X-Coordination-Internal-Key"

# --- ELR-owned key file (ENC-TSK-Q35 / ENC-ISS-831) -----------------------
# ELR's own durable credential source, resolved here in Python so every
# entry point (the wrapper, a direct ``python3 elr_<sub>.py``, a subagent,
# a Workflow script) finds the same key. It is consulted AFTER the env
# chain above (an explicit env var still wins) and must be a regular file
# readable by the owner only (mode 0600 or 0400): anything wider is
# ignored with a warning, never used. ELR never reads ~/.claude.json or any
# other MCP launcher config. io provisions the file with
# tools/elr/elr_provision_key.py; agents never write it.
ELR_KEY_FILE_ENV = "ENCELADUS_ELR_KEY_FILE"
ELR_KEY_FILE_DEFAULT = "~/.enceladus/internal_key"

# Exit code and anomaly for an auth-required read with no credential at all
# (ENC-TSK-Q35 AC-4). Codes 1-6 are taken (see elr_lib/tls.py,
# elr_list.py, elr_doc_patch.py).
EXIT_CODE_NO_CREDENTIAL = 7
NO_CREDENTIAL_STATUS = "no_credential"
NO_CREDENTIAL_ANOMALY = "no_credential_configured"
NO_CREDENTIAL_REMEDIATION = (
    "no ELR credential: have io run `python3 tools/elr/elr_provision_key.py` "
    "(writes ~/.enceladus/internal_key at 0600), or set ENCELADUS_INTERNAL_API_KEY; "
    "ELR does not read ~/.claude.json (ENC-ISS-831)"
)


def elr_key_file_path() -> Path:
    return Path(os.environ.get(ELR_KEY_FILE_ENV, "").strip() or ELR_KEY_FILE_DEFAULT).expanduser()


def read_elr_key_file(path: Optional[Path] = None) -> Tuple[str, List[str]]:
    """Return (key, warnings) from the ELR key file. The key is "" when the
    file is absent, unreadable, empty, or not owner-only. Warnings name the
    problem and never include the file's contents."""
    target = path or elr_key_file_path()
    try:
        st = target.stat()
    except FileNotFoundError:
        return "", []
    except OSError as exc:
        return "", [f"elr_key_file_unreadable: {target} ({exc.__class__.__name__})"]
    if not stat.S_ISREG(st.st_mode):
        return "", [f"elr_key_file_not_regular: {target}"]
    if st.st_mode & 0o077:
        return "", [f"elr_key_file_mode_insecure: {target} is {oct(st.st_mode & 0o777)}, need 0600 -- ignored"]
    try:
        value = target.read_text(encoding="utf-8").strip()
    except OSError as exc:
        return "", [f"elr_key_file_unreadable: {target} ({exc.__class__.__name__})"]
    if not value:
        return "", [f"elr_key_file_empty: {target}"]
    return value, []


def resolve_common_internal_key() -> Tuple[str, str]:
    """(value, source) for the common internal key: the env chain first,
    then the ELR key file. ``source`` is an env var NAME, "key_file", or
    "none" -- never the value."""
    for env_name in COMMON_INTERNAL_KEY_ENV_CHAIN:
        value = os.environ.get(env_name, "").strip()
        if value:
            return value, env_name
    value, _warnings = read_elr_key_file()
    if value:
        return value, "key_file"
    return "", "none"

DEFAULT_USER_AGENT_ENV = "ENCELADUS_HTTP_USER_AGENT"
DEFAULT_USER_AGENT = "enceladus-elr-core/1.0"

# --- mcp-http profile ----------------------------------------------------
MCP_GATEWAY_URL_ENV = "ENCELADUS_MCP_GATEWAY_URL"
MCP_GATEWAY_URL_DEFAULT = "https://jreese.net/api/v1/coordination/mcp"
# Optional bearer source chain: a caller-supplied bearer/id-token first
# (e.g. a Cognito id_token minted via coordination.auth.cognito_session),
# falling back to the static gateway key server.py validates as
# ``Authorization: Bearer <ENCELADUS_MCP_API_KEY>`` (server.py MCP_API_KEY).
MCP_BEARER_ENV_CHAIN = (
    "ENCELADUS_MCP_BEARER_TOKEN",
    "ENCELADUS_MCP_API_KEY",
)


def _mask(value: str) -> str:
    """Never echo a secret -- report only whether it is set."""
    return "<set>" if value else "<unset>"


class InternalProfileConfig:
    """Resolved config for the "internal" profile.

    Base URLs and credentials are snapshotted from the environment at
    construction time so a single instance behaves consistently across a
    run even if the environment mutates.
    """

    def __init__(self, environment_profile: Optional["elr_profiles.EnvironmentProfile"] = None) -> None:
        self.profile = PROFILE_INTERNAL
        # ENC-TSK-P77: WHICH deployed environment (prod/v4-gamma), a
        # separate axis from `self.profile` above (the transport shape).
        # Resolution order per-api below: explicit ENCELADUS_<API>_API_BASE
        # env var (unchanged, always wins) -> this environment profile's
        # api_base_overrides -> the static _API_BASE_DEFAULTS default.
        self.environment_profile = environment_profile or elr_profiles.get_environment_profile()
        self.user_agent = os.environ.get(DEFAULT_USER_AGENT_ENV, DEFAULT_USER_AGENT)
        self._bases: Dict[str, str] = {
            api: (
                os.environ.get(env_name, "").strip()
                or self.environment_profile.api_base_overrides.get(api)
                or default
            )
            for api, (env_name, default) in _API_BASE_DEFAULTS.items()
        }
        self._keys: Dict[str, str] = {api: self._resolve_key(api) for api in _API_BASE_DEFAULTS}

    @staticmethod
    def _resolve_key(api: str) -> str:
        if api == "health":
            return ""
        dedicated_env = _DEDICATED_KEY_ENV.get(api)
        if dedicated_env:
            value = os.environ.get(dedicated_env, "").strip()
            if value:
                return value
        value, _source = resolve_common_internal_key()
        return value

    def base_url(self, api: str) -> str:
        try:
            return self._bases[api]
        except KeyError as exc:
            raise ValueError(
                f"unknown ELR api {api!r}; expected one of {sorted(_API_BASE_DEFAULTS)}"
            ) from exc

    def key_for(self, api: str) -> str:
        if api not in self._bases:
            raise ValueError(
                f"unknown ELR api {api!r}; expected one of {sorted(_API_BASE_DEFAULTS)}"
            )
        return self._keys.get(api, "")

    def apis(self) -> Tuple[str, ...]:
        return tuple(sorted(self._bases))

    def __repr__(self) -> str:
        keys_configured = {api: bool(v) for api, v in self._keys.items()}
        return (
            f"InternalProfileConfig(user_agent={self.user_agent!r}, "
            f"bases={self._bases!r}, keys_configured={keys_configured!r})"
        )


class McpHttpProfileConfig:
    """Resolved config for the "mcp-http" profile."""

    def __init__(self, environment_profile: Optional["elr_profiles.EnvironmentProfile"] = None) -> None:
        self.profile = PROFILE_MCP_HTTP
        self.environment_profile = environment_profile or elr_profiles.get_environment_profile()
        # ENC-TSK-P77: an explicit ENCELADUS_MCP_GATEWAY_URL always wins;
        # otherwise the gateway URL is derived from this environment
        # profile's coordination_base_url (mirrors server.py's own
        # <coordination base>/mcp routing), replacing the old
        # hardcoded-to-prod MCP_GATEWAY_URL_DEFAULT.
        env_gateway_url = os.environ.get(MCP_GATEWAY_URL_ENV, "").strip()
        self.gateway_url = env_gateway_url or f"{self.environment_profile.coordination_base_url}/mcp"
        self.user_agent = os.environ.get(DEFAULT_USER_AGENT_ENV, DEFAULT_USER_AGENT)
        self._bearer = ""
        for env_name in MCP_BEARER_ENV_CHAIN:
            value = os.environ.get(env_name, "").strip()
            if value:
                self._bearer = value
                break

    @property
    def bearer_configured(self) -> bool:
        return bool(self._bearer)

    def bearer_token(self) -> str:
        return self._bearer

    def __repr__(self) -> str:
        return (
            f"McpHttpProfileConfig(gateway_url={self.gateway_url!r}, "
            f"user_agent={self.user_agent!r}, bearer={_mask(self._bearer)})"
        )


def get_profile(name: str = PROFILE_INTERNAL, environment_profile_name: Optional[str] = None):
    """Resolve a TRANSPORT profile config object (`name`: "internal" /
    "mcp-http") -- unchanged contract, raises ValueError for anything
    else.

    `environment_profile_name` (ENC-TSK-P77) is the SEPARATE, ENVIRONMENT
    axis (e.g. a script's --profile / ENCELADUS_PROFILE value: "prod" /
    "v4-gamma"). It resolves via elr_lib.profiles.get_environment_profile
    (which itself fails fast, listing valid names, for an unknown value)
    and is threaded into whichever transport config is built so its
    per-API base-URL defaults (and, for mcp-http, its gateway URL) point
    at that environment.
    """
    normalized = (name or PROFILE_INTERNAL).strip().lower()
    environment_profile = elr_profiles.get_environment_profile(environment_profile_name)
    if normalized == PROFILE_INTERNAL:
        return InternalProfileConfig(environment_profile=environment_profile)
    if normalized == PROFILE_MCP_HTTP:
        return McpHttpProfileConfig(environment_profile=environment_profile)
    raise ValueError(f"unknown ELR profile {name!r}; expected one of {VALID_PROFILES}")
