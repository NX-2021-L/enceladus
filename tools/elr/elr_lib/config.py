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
from typing import Dict, Optional, Tuple

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
COMMON_INTERNAL_KEY_ENV_CHAIN = (
    "ENCELADUS_COORDINATION_API_INTERNAL_API_KEY",
    "ENCELADUS_COORDINATION_INTERNAL_API_KEY",
    "COORDINATION_INTERNAL_API_KEY",
    "COORDINATION_INTERNAL_API_KEY_PREVIOUS",
)

# Auth header name, verbatim from server.py.
INTERNAL_AUTH_HEADER = "X-Coordination-Internal-Key"

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

    def __init__(self) -> None:
        self.profile = PROFILE_INTERNAL
        self.user_agent = os.environ.get(DEFAULT_USER_AGENT_ENV, DEFAULT_USER_AGENT)
        self._bases: Dict[str, str] = {
            api: os.environ.get(env_name, default).strip() or default
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
        for env_name in COMMON_INTERNAL_KEY_ENV_CHAIN:
            value = os.environ.get(env_name, "").strip()
            if value:
                return value
        return ""

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

    def __init__(self) -> None:
        self.profile = PROFILE_MCP_HTTP
        self.gateway_url = os.environ.get(MCP_GATEWAY_URL_ENV, MCP_GATEWAY_URL_DEFAULT).strip() or MCP_GATEWAY_URL_DEFAULT
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


def get_profile(name: str = PROFILE_INTERNAL):
    """Resolve a profile config object by name.

    Raises ValueError for anything other than "internal" / "mcp-http".
    """
    normalized = (name or PROFILE_INTERNAL).strip().lower()
    if normalized == PROFILE_INTERNAL:
        return InternalProfileConfig()
    if normalized == PROFILE_MCP_HTTP:
        return McpHttpProfileConfig()
    raise ValueError(f"unknown ELR profile {name!r}; expected one of {VALID_PROFILES}")
