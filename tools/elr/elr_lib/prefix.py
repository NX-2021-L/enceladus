"""elr_lib/prefix.py -- live prefix -> project_id resolution.

ENC-TSK-P90 / T-B1b (FR-B4-3, ELR half of ENC-TSK-P74). Replaces the old
static ``_PREFIX_TO_PROJECT_ID = {"ENC": "enceladus"}`` literal that used
to live in elr_batch_get.py with a resolver backed by the live
``projects.prefix_map`` MCP code-mode search action (server-side landed
in ENC-TSK-P74 / FR-B4-2: tools/enceladus-mcp-server/server.py's
``_projects_prefix_map``, reusing the ``_get_prefix_map()`` resolver
verbatim -- see governance_data_dictionary.json's
``mcp_server.projects_prefix_map`` entity).

Resolution precedence, per run, the FIRST time any prefix actually needs
resolving (never eagerly -- a batch of only DOC-* ids never touches this
at all, and reports prefix_map_source "none"):

  1. A LOCAL FILE CACHE at ~/.enceladus/prefix_map.json, if it exists AND
     is within its 300s TTL (judged by *our own* locally-written
     ``generated_at`` epoch timestamp, not the server's ISO-8601 one --
     this avoids any clock-skew/timezone parsing hazard between this
     workstation and the server). source="cache".
  2. Otherwise, ONE live network fetch via the ELR mcp-http transport
     (elr_lib.transport.McpHttpClient), JSON-RPC tools/call
     {name: "search", arguments: {action: "projects.prefix_map",
     arguments: {}}} -> result {prefixes, source, generated_at}. On
     success the file cache is refreshed. source="network".
  3. If the network call fails and a cache file exists (even if stale --
     "stale" beats "nothing"), fall back to it. source="cache", plus an
     anomaly noting the cache was stale-served.
  4. Only when NEITHER a live network map NOR any cached file (fresh or
     stale) is available does resolution fall back to a built-in
     ENC->enceladus seed -- reported explicitly as source="builtin" plus
     an anomaly, never silently treated as equivalent to a live map.

An unknown prefix (absent from whatever map source was ultimately used)
is NEVER guessed at -- resolve_prefix() returns None, and the caller
(elr_batch_get.py's classify_id) is responsible for reporting that id as
unclassified in its digest, alongside this resolver's ``source``.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import config as elr_config
from .transport import McpHttpClient

DEFAULT_CACHE_PATH = Path("~/.enceladus/prefix_map.json").expanduser()
CACHE_TTL_SECONDS = 300

SOURCE_NETWORK = "network"
SOURCE_CACHE = "cache"
SOURCE_NONE = "none"
SOURCE_BUILTIN = "builtin"
VALID_SOURCES: Tuple[str, ...] = (SOURCE_NETWORK, SOURCE_CACHE, SOURCE_NONE, SOURCE_BUILTIN)

# Last-resort seed -- see module docstring precedence step 4. Never used
# unless BOTH the network call and any cached file (fresh or stale) are
# unavailable.
BUILTIN_SEED: Dict[str, str] = {"ENC": "enceladus"}

# A record id's leading PREFIX- segment, e.g. "ENC" out of "ENC-TSK-1" or
# "INT" out of "INT-TSK-4". Deliberately permissive about what follows --
# this module only ever resolves the prefix segment itself; the caller
# (elr_batch_get.classify_id) is responsible for validating the rest of
# the id shape.
_PREFIX_RE = re.compile(r"^(?P<prefix>[A-Z]{2,8})-")


def extract_prefix(record_id: str) -> Optional[str]:
    """Pull the leading PREFIX- segment off a record id, upper-cased.

    Returns None for anything that doesn't look like "PREFIX-..." at all
    (e.g. a bare DOC id fragment or garbage input) -- callers must treat
    None as "no prefix to resolve", not as an unknown prefix.
    """
    if not record_id:
        return None
    match = _PREFIX_RE.match(str(record_id).strip().upper())
    return match.group("prefix") if match else None


def _read_cache(cache_path: Path) -> Optional[Dict[str, Any]]:
    try:
        raw = cache_path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    prefixes = data.get("prefixes")
    if not isinstance(prefixes, dict) or "generated_at" not in data:
        return None
    return data


def _write_cache(cache_path: Path, prefixes: Dict[str, str]) -> None:
    # Best-effort only: a cache-write failure (read-only home dir, full
    # disk, ...) must never fail the run over what is purely a local
    # speed-up.
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"prefixes": prefixes, "generated_at": time.time()}
        cache_path.write_text(json.dumps(payload), encoding="utf-8")
    except OSError:
        pass


def _cache_is_fresh(cache_entry: Dict[str, Any], ttl_seconds: float) -> bool:
    try:
        generated_at = float(cache_entry["generated_at"])
    except (KeyError, TypeError, ValueError):
        return False
    return (time.time() - generated_at) <= ttl_seconds


def _fetch_from_network(mcp_config: Any, timeout: int) -> Tuple[Optional[Dict[str, str]], List[str]]:
    """One attempt at the live projects.prefix_map search action.

    Returns (prefixes_or_None, anomalies). Never raises -- a transport
    bug degrades to a reported anomaly + None, same as any other network
    failure, so the caller can fall through to cache/builtin.
    """
    try:
        client = McpHttpClient(mcp_config, timeout=timeout)
        outcome = client.call_tool("search", {"action": "projects.prefix_map", "arguments": {}})
    except Exception as exc:  # pragma: no cover - defense in depth only
        return None, [f"prefix_map_network_exception:{exc}"]

    if outcome.is_error or not (200 <= outcome.status < 300):
        return None, [f"prefix_map_network_failed:status={outcome.status}"]

    result = outcome.result
    if not isinstance(result, dict) or not isinstance(result.get("prefixes"), dict):
        return None, ["prefix_map_network_malformed_response"]

    prefixes = {str(k).strip().upper(): str(v) for k, v in result["prefixes"].items()}
    return prefixes, []


class PrefixResolver:
    """Resolves record-id prefixes to project_id for ONE run.

    The map is fetched at most once per instance ("fetched once per
    run") -- construct a single PrefixResolver per CLI invocation and
    reuse it for every id classified during that run; the underlying
    fetch/cache/builtin resolution happens lazily, on the first call to
    resolve_prefix() that actually needs it, not at construction time.
    """

    def __init__(
        self,
        environment_profile_name: Optional[str] = None,
        timeout: int = 10,
        cache_path: Optional[Path] = None,
        cache_ttl_seconds: float = CACHE_TTL_SECONDS,
    ) -> None:
        self._environment_profile_name = environment_profile_name
        self._timeout = timeout
        self._cache_path = Path(cache_path) if cache_path else DEFAULT_CACHE_PATH
        self._cache_ttl_seconds = cache_ttl_seconds
        self._mapping: Optional[Dict[str, str]] = None
        self._source: str = SOURCE_NONE
        self._anomalies: List[str] = []

    @classmethod
    def from_mapping(cls, mapping: Dict[str, str], source: str = SOURCE_NONE) -> "PrefixResolver":
        """Build a resolver already seeded with a fixed map -- never
        touches the network or the filesystem. Used by tests (and any
        caller that has already resolved a map by some other means) that
        want deterministic, offline prefix resolution.
        """
        resolver = cls()
        resolver._mapping = {str(k).strip().upper(): str(v) for k, v in mapping.items()}
        resolver._source = source
        return resolver

    @property
    def source(self) -> str:
        """The provenance of whatever map (if any) was actually used this
        run: "network" / "cache" / "builtin" / "none" (none = resolution
        was never needed -- no id required a prefix lookup)."""
        return self._source

    @property
    def anomalies(self) -> List[str]:
        return list(self._anomalies)

    def _ensure_mapping(self) -> Dict[str, str]:
        if self._mapping is not None:
            return self._mapping

        cache_entry = _read_cache(self._cache_path)

        if cache_entry is not None and _cache_is_fresh(cache_entry, self._cache_ttl_seconds):
            self._mapping = dict(cache_entry["prefixes"])
            self._source = SOURCE_CACHE
            return self._mapping

        mcp_config = elr_config.get_profile(
            elr_config.PROFILE_MCP_HTTP, environment_profile_name=self._environment_profile_name
        )
        prefixes, fetch_anomalies = _fetch_from_network(mcp_config, self._timeout)

        if prefixes is not None:
            self._mapping = prefixes
            self._source = SOURCE_NETWORK
            _write_cache(self._cache_path, prefixes)
            return self._mapping

        self._anomalies.extend(fetch_anomalies)

        if cache_entry is not None:
            # Stale cache beats no cache at all (AC-1).
            self._mapping = dict(cache_entry["prefixes"])
            self._source = SOURCE_CACHE
            self._anomalies.append("prefix_map_stale_cache_used")
            return self._mapping

        # Neither a live network map nor any cached file (fresh or
        # stale) is available. The built-in ENC seed is the explicitly
        # reported last resort -- see module docstring precedence step 4.
        self._mapping = dict(BUILTIN_SEED)
        self._source = SOURCE_BUILTIN
        self._anomalies.append("prefix_map_builtin_seed_used")
        return self._mapping

    def resolve_prefix(self, record_id: str) -> Optional[str]:
        """Resolve one record id's project_id.

        Returns None -- NEVER a guess -- both when the id has no
        recognizable PREFIX- segment at all, and when its prefix is
        simply absent from whatever map source ended up being used this
        run. The caller is responsible for reporting the latter case as
        unclassified.
        """
        prefix = extract_prefix(record_id)
        if prefix is None:
            return None
        return self._ensure_mapping().get(prefix)


def resolve_prefix(record_id: str, resolver: Optional[PrefixResolver] = None, **resolver_kwargs: Any) -> Optional[str]:
    """Module-level convenience wrapper around PrefixResolver.resolve_prefix.

    Prefer constructing one PrefixResolver per run and calling its
    .resolve_prefix() method directly when resolving more than one id, so
    the map is fetched only once ("fetched once per run"); this free
    function builds a throwaway resolver when none is supplied, which is
    fine for a single one-off lookup but wasteful (and non-cached across
    the *same* PrefixResolver instance) for a batch.
    """
    resolver = resolver or PrefixResolver(**resolver_kwargs)
    return resolver.resolve_prefix(record_id)
