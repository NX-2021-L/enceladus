"""Signed v1 feed cursors (DVP-TSK-919, @io-kit/feed 1.0 cursor_shape).

Wire form (byte-compatible with ``createCursorCodec`` in @io-kit/feed):

    base64url(JSON{v:1, k, f, scope, exp, kid}) + "." + base64url(HMAC-SHA256(body))

* payload keys are sorted and compact; ``exp`` is epoch SECONDS;
* the HMAC is taken over the ASCII payload segment;
* ``f`` = base64url(first 12 bytes of sha256(stable-JSON(filter))) -- the kit's ``hashFilter``;
* ``k`` is the ordering key only (never a DynamoDB LastEvaluatedKey);
* ``kid`` selects the HMAC key, so keys rotate by adding a new kid and moving the active kid.

Key material (no new infra): ``FEED_CURSOR_KEYS`` (JSON ``{"kid": "secret"}``) and
``FEED_CURSOR_ACTIVE_KID``; when unset, one key is derived from the lambda's existing
``COORDINATION_INTERNAL_API_KEY`` (kid ``ik1``). With no key at all the lambda keeps
minting the legacy unsigned cursor, so a deploy never breaks paging.

Migration: the unsigned v0 cursor is accepted until ``V0_ACCEPTANCE_END`` (2027-01-10,
the kit's window) and rejected afterwards.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

V0_ACCEPTANCE_END_MS = int(datetime(2027, 1, 10, tzinfo=timezone.utc).timestamp() * 1000)
DEFAULT_TTL_S = 24 * 60 * 60
DERIVED_KID = "ik1"


class CursorInvalid(Exception):
    """Maps to HTTP 400 ``cursor_invalid``."""

    code = "cursor_invalid"
    status = 400

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode((text + "=" * (-len(text) % 4)).encode("ascii"))


def _stable(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hash_filter(filter_value: Any = None) -> str:
    """The kit's ``hashFilter``: key-order independent, 12 bytes of sha256."""
    digest = hashlib.sha256(_stable({} if filter_value is None else filter_value).encode("utf-8")).digest()
    return _b64e(digest[:12])


def load_keys() -> Tuple[Dict[str, str], Optional[str]]:
    raw = os.environ.get("FEED_CURSOR_KEYS", "").strip()
    keys: Dict[str, str] = {}
    if raw:
        try:
            parsed = json.loads(raw)
            keys = {str(k): str(v) for k, v in parsed.items() if v}
        except (ValueError, AttributeError):
            keys = {}
    base = os.environ.get("COORDINATION_INTERNAL_API_KEY", "")
    if base and DERIVED_KID not in keys:
        keys[DERIVED_KID] = hmac.new(base.encode("utf-8"), b"feed_query.cursor.v1", hashlib.sha256).hexdigest()
    if not keys:
        return {}, None
    active = os.environ.get("FEED_CURSOR_ACTIVE_KID", "").strip()
    if active not in keys:
        active = sorted(keys)[0]
    return keys, active


def encode(k: str, scope: str, filter_value: Any = None, *, now: Optional[float] = None,
           ttl_s: int = DEFAULT_TTL_S) -> Optional[str]:
    """Mint a signed v1 cursor, or None when no signing key is configured."""
    keys, kid = load_keys()
    if not kid:
        return None
    payload = {
        "v": 1, "k": k, "f": hash_filter(filter_value), "scope": scope,
        "exp": int((time.time() if now is None else now)) + ttl_s, "kid": kid,
    }
    body = _b64e(_stable(payload).encode("utf-8"))
    tag = hmac.new(keys[kid].encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()
    return f"{body}.{_b64e(tag)}"


def decode(raw: str, scope: str, filter_value: Any = None, *, now: Optional[float] = None) -> Tuple[str, int]:
    """Verify a cursor and return ``(k, version)``; raises CursorInvalid.

    Version 1 = signed. Version 0 = legacy unsigned, returned as the raw opaque text for the
    caller to parse; only inside the migration window.
    """
    clock = time.time() if now is None else now
    if "." not in raw:
        if int(clock * 1000) >= V0_ACCEPTANCE_END_MS:
            raise CursorInvalid("unsigned_not_allowed")
        return raw, 0
    parts = raw.split(".")
    if len(parts) != 2 or not all(parts):
        raise CursorInvalid("malformed")
    body, tag = parts
    try:
        payload = json.loads(_b64d(body).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise CursorInvalid("malformed")
    if not isinstance(payload, dict) or payload.get("v") != 1:
        raise CursorInvalid("bad_version")
    keys, _ = load_keys()
    secret = keys.get(str(payload.get("kid")))
    if secret is None:
        raise CursorInvalid("unknown_kid")
    want = hmac.new(secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()
    try:
        got = _b64d(tag)
    except ValueError:
        raise CursorInvalid("malformed")
    if not hmac.compare_digest(want, got):
        raise CursorInvalid("bad_tag")
    if not isinstance(payload.get("exp"), (int, float)) or payload["exp"] < clock:
        raise CursorInvalid("expired")
    if payload.get("scope") != scope:
        raise CursorInvalid("foreign_scope")
    if payload.get("f") != hash_filter(filter_value):
        raise CursorInvalid("foreign_filter")
    k = payload.get("k")
    if not isinstance(k, str) or not k:
        raise CursorInvalid("unsafe_key")
    return k, 1
