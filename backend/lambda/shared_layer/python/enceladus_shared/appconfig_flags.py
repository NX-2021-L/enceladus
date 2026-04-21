"""
AppConfig feature flag reader — ENC-TSK-F63 AC-1.

Replaces ENABLE_* env var reads with AppConfig extension HTTP polling.
The AppConfig Lambda extension (layer AWS-AppConfig-Extension) runs on
localhost:2772 and serves cached config; calls are sub-millisecond after
the first warm fetch. Falls back to env var values for local dev / test
environments where the extension is not running.
"""
import json
import os
import time
import urllib.error
import urllib.request

_APPCONFIG_PORT = int(os.environ.get("AWS_APPCONFIG_EXTENSION_HTTP_PORT", "2772"))
_CACHE: dict = {}
_CACHE_AT: float = 0.0
_CACHE_TTL: float = float(os.environ.get("AWS_APPCONFIG_EXTENSION_POLL_INTERVAL_SECONDS", "45"))


def _fetch() -> dict:
    app = os.environ.get("APPCONFIG_APPLICATION", "enceladus")
    env = os.environ.get("APPCONFIG_ENVIRONMENT", "production")
    cfg = os.environ.get("APPCONFIG_CONFIGURATION", "feature-flags")
    url = f"http://localhost:{_APPCONFIG_PORT}/applications/{app}/environments/{env}/configurations/{cfg}"
    try:
        with urllib.request.urlopen(url, timeout=1) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, OSError):
        return {}


def get_flags() -> dict:
    """Return the current feature flag dict; serves from cache within TTL."""
    global _CACHE, _CACHE_AT
    now = time.monotonic()
    if not _CACHE or now - _CACHE_AT >= _CACHE_TTL:
        fresh = _fetch()
        if fresh:
            _CACHE = fresh
            _CACHE_AT = now
    return _CACHE


def flag(name: str, *, env_fallback: str | None = None, default: bool = False) -> bool:
    """
    Read a boolean feature flag by name.

    Resolution order:
      1. AppConfig (if extension is reachable)
      2. env_fallback env var (for local dev / legacy compat)
      3. default

    name        — key in AppConfig JSON, e.g. "enable_lesson_primitive"
    env_fallback — optional ENABLE_* env var name to try when AppConfig is unreachable
    default     — hardcoded fallback when neither source is available
    """
    flags = get_flags()
    if name in flags:
        val = flags[name]
        return bool(val) if not isinstance(val, bool) else val
    if env_fallback:
        raw = os.environ.get(env_fallback, "").strip().lower()
        if raw:
            return raw == "true"
    return default
