"""S3 cycle-artifact read/write (DOC-BDDE755DB874 §5.1)."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import boto3

from config import S3_BUCKET, artifact_prefix

logger = logging.getLogger(__name__)
_s3 = boto3.client("s3")


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
        resp = _s3.get_object(Bucket=S3_BUCKET, Key=key)
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
        _s3.put_object(
            Bucket=S3_BUCKET,
            Key=key,
            Body=body,
            ContentType="application/json",
        )
    return {"timestamped_key": ts_key, "latest_key": latest, "bytes": str(len(body))}
