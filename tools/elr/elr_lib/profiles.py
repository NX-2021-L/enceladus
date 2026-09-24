"""ELR ENVIRONMENT profiles (ENC-TSK-P77, T-B4, FR-B4-10).

NAMING NOTE -- two DISTINCT "profile" concepts exist in ELR; do not
conflate them:

  * elr_lib.config's existing TRANSPORT profile ("internal" / "mcp-http")
    picks WHICH PROTOCOL/CLIENT SHAPE ELR speaks (direct governed-API
    HTTPS calls vs the JSON-RPC MCP-over-HTTP gateway). Selected via
    elr_lib.config.get_profile(name=...).

  * This module's ENVIRONMENT profile ("prod" / "v4-gamma") picks WHICH
    DEPLOYED ENCELADUS ENVIRONMENT ELR talks to -- i.e. which host every
    base URL points at. Selected via ENCELADUS_PROFILE (env) or a
    script's --profile CLI flag, resolved with get_environment_profile().

Every ELR CLI's `--profile` flag is this ENVIRONMENT profile (per the
ENC-TSK-P77 AC text) -- the transport-profile axis is not independently
CLI-selectable today (every script already hardcoded transport profile
"internal" as its only real choice before this change), so there is no
flag-name collision in practice, but the two concepts stay separate
objects/functions in code so a future transport-profile CLI flag can be
added without touching this module.

An EnvironmentProfile carries:
  - mcp_base_url          -- the full MCP server host for this environment
                              (reference/reporting; ELR's own "mcp-http"
                              transport talks to a gateway URL derived
                              from coordination_base_url, see config.py).
  - coordination_base_url -- the coordination API base for this environment.
  - api_base_overrides    -- the same per-API base-URL defaults
                              elr_lib.config.InternalProfileConfig's
                              _API_BASE_DEFAULTS table uses, keyed
                              identically (e.g. "tracker", "document"),
                              but pointed at this environment's host.

Explicit ENCELADUS_<API>_API_BASE env vars (elr_lib.config's existing
per-API override chain) ALWAYS win over an environment profile's
api_base_overrides -- an environment profile only supplies a new
DEFAULT layer, never a forced override.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

ENV_PROFILE_ENV_VAR = "ENCELADUS_PROFILE"

PROFILE_PROD = "prod"
PROFILE_V4_GAMMA = "v4-gamma"
VALID_ENVIRONMENT_PROFILES: Tuple[str, ...] = (PROFILE_PROD, PROFILE_V4_GAMMA)

_PROD_API_HOST = "https://jreese.net"
_GAMMA_API_HOST = "https://enceladus-gamma.jreese.net"

# Path suffixes mirrored verbatim from elr_lib.config._API_BASE_DEFAULTS
# for every api whose PROD default already lives under
# <host>/api/v1/<path>. "graph_query" is DELIBERATELY EXCLUDED: its prod
# default is a direct API-Gateway execute-api URL
# (https://8nkzqkmxqc.../api/v1/tracker/graphsearch), not a jreese.net
# path, and no verified v4-gamma execute-api id was available at
# authoring time -- under the v4-gamma profile it silently falls back to
# config.py's own (prod) graph_query default until that gap is closed
# (tracked as a follow-up, not part of FR-B4-10's ask).
_MIRRORED_API_PATHS: Dict[str, str] = {
    "coordination": "/api/v1/coordination",
    "document": "/api/v1/documents",
    "deploy": "/api/v1/deploy",
    "changelog": "/api/v1/changelog",
    "tracker": "/api/v1/tracker",
    "checkout": "/api/v1/checkout",
    "governance": "/api/v1/governance",
    "projects": "/api/v1/coordination/projects",
    "health": "/api/v1/health",
    "github": "/api/v1/github",
}


def _mirrored_overrides(host: str) -> Dict[str, str]:
    return {api: f"{host}{path}" for api, path in _MIRRORED_API_PATHS.items()}


@dataclass(frozen=True)
class EnvironmentProfile:
    name: str
    mcp_base_url: str
    coordination_base_url: str
    api_base_overrides: Dict[str, str] = field(default_factory=dict)
    # ENC-TSK-P79: plane-safety sentinel document that exists ONLY on this
    # environment; elr_lib.plane_safety proves the plane it is writing to by
    # asking the target to echo this id. Prod keeps the historical constant.
    sentinel_document_id: str = "DOC-87EC08ECF51A"


_PROFILES: Dict[str, EnvironmentProfile] = {
    PROFILE_PROD: EnvironmentProfile(
        name=PROFILE_PROD,
        mcp_base_url="https://mcp.jreese.net",
        coordination_base_url=f"{_PROD_API_HOST}/api/v1/coordination",
        api_base_overrides=_mirrored_overrides(_PROD_API_HOST),
    ),
    PROFILE_V4_GAMMA: EnvironmentProfile(
        name=PROFILE_V4_GAMMA,
        mcp_base_url="https://mcp-gamma.jreese.net",
        coordination_base_url=f"{_GAMMA_API_HOST}/api/v1/coordination",
        api_base_overrides=_mirrored_overrides(_GAMMA_API_HOST),
        sentinel_document_id="DOC-EF02AE82AD3A",
    ),
}


def get_environment_profile(name: Optional[str] = None) -> EnvironmentProfile:
    """Resolve an ENVIRONMENT profile by name.

    Resolution order: explicit `name` arg (e.g. a CLI --profile value) if
    given and non-empty, else the ENCELADUS_PROFILE env var, else "prod".

    Raises ValueError -- listing the valid names -- for anything not in
    VALID_ENVIRONMENT_PROFILES, per AC-1's fail-fast requirement.
    """
    resolved = (name or "").strip() or os.environ.get(ENV_PROFILE_ENV_VAR, "").strip() or PROFILE_PROD
    try:
        return _PROFILES[resolved]
    except KeyError as exc:
        raise ValueError(
            f"unknown ELR environment profile {resolved!r}; expected one of {VALID_ENVIRONMENT_PROFILES}"
        ) from exc


def environment_profile_names() -> Tuple[str, ...]:
    return VALID_ENVIRONMENT_PROFILES
