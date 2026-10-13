"""S3 cycle-artifact read/write (DOC-BDDE755DB874 §5.1)."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import boto3

from config import S3_BUCKET, artifact_prefix

logger = logging.getLogger(__name__)
_s3 = boto3.client("s3")
_STORE: Any = None


def content_store(client: Any = None) -> Any:
    """DVP-TSK-B39 (isolation W4k): every rhythm-cycle/ object access goes through content_store.

    CONTENT_STORE_MODE=dual writes the per-environment content bucket (key without the legacy-only S3_ENV_PREFIX) AND
    S3_BUCKET (legacy); CONTENT_STORE_READ=legacy keeps read_latest and the tenant stanza list/get on S3_BUCKET until
    every writer of the prefix (this function and the heavy-beat tenants) is dual. legacy (default) is byte-identical
    to a raw s3 call. Bound to the given client (default this module's _s3); rebuilt when the client changes.
    """
    global _STORE
    client = _s3 if client is None else client
    if _STORE is None or _STORE.s3 is not client:
        try:
            from content_store import ContentStore  # shipped to the function root by .build_extras
        except ImportError:  # local tests: the canonical shared-layer copy
            from enceladus_shared.content_store import ContentStore
        _STORE = ContentStore.from_env(client, dict(os.environ, LEGACY_BUCKET=S3_BUCKET))
    return _STORE


def _tier_base(tier: str) -> str:
    return f"{artifact_prefix()}/{tier}"


def artifact_key(tier: str, beat_ts: datetime) -> str:
    """Timestamped artifact: {prefix}/{tier}/{YYYY}/{MM}/{DD}/{HHmmss}.json"""
    ts = beat_ts.astimezone(timezone.utc)
    return (
        f"{_tier_base(tier)}/{ts.year:04d}/{ts.month:02d}/{ts.day:02d}/"
        f"{ts.hour:02d}{ts.minute:02d}{ts.second:02d}.json"
    )


def latest_key(tier: str) -> str:
    return f"{_tier_base(tier)}/latest.json"


def read_latest(tier: str) -> Optional[Dict[str, Any]]:
    key = latest_key(tier)
    try:
        resp = content_store().get_object(key)  # DVP-TSK-B39: legacy-pinned until every writer is dual
        body = resp["Body"].read().decode("utf-8")
        return json.loads(body)
    except _s3.exceptions.NoSuchKey:
        return None
    except Exception as exc:
        logger.warning("read_latest(%s) failed: %s", tier, exc)
        return None


def write_artifact(tier: str, payload: Dict[str, Any], beat_ts: Optional[datetime] = None) -> Dict[str, str]:
    beat_ts = beat_ts or datetime.now(timezone.utc)
    payload = dict(payload)
    payload.setdefault("tier", tier)
    payload.setdefault("beat_at", beat_ts.isoformat())

    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ts_key = artifact_key(tier, beat_ts)
    latest = latest_key(tier)

    for key in (ts_key, latest):
        content_store().put_object(  # DVP-TSK-B39: dual mode writes the content bucket, then S3_BUCKET
            key,
            body,
            ContentType="application/json",
        )
    return {"timestamped_key": ts_key, "latest_key": latest, "bytes": str(len(body))}
