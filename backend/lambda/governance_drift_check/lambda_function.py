"""Governance drift-detection backstop — canonical record vs. live S3 reconcile.

ENC-TSK-I32 / ENC-FTR-116 — DOC-6F7A14667E7D §8 ("the drift backstop") + §3
("a drift backstop reconciles").

The storage-event recompute Lambda (``recompute_governance``) keeps the canonical
``governance-version`` DynamoDB record in agreement with live S3 by reacting to
``s3:ObjectCreated`` events. S3 event delivery is at-least-once and unordered,
and an event can in principle be lost; the recompute can also fail. This Lambda
is the Argo/FIM-style backstop: on a schedule it independently recomputes the
§4.3 bundle hash from current live S3 object checksums and compares it against
the stored canonical record. Disagreement (or a failed recompute, or a missing
record) is surfaced as:

  * a CloudWatch metric ``GovernanceVersionDrift`` (1.0 = drift, 0.0 = agree) in
    namespace ``Enceladus/Governance`` — a CloudWatch alarm fires on this; and
  * an SNS alert (same topic/style as the governance_audit anomaly detector).

Read-only with respect to governance: this Lambda NEVER writes the canonical
record (that is the recompute Lambda's sole-writer responsibility, I28) and never
writes back to ``governance/live/*`` (recursion safety). It only reads S3 + DDB
and emits a metric / alert.

The §4.3 hashing contract below MUST stay byte-for-byte in sync with
``recompute_governance/lambda_function.py`` — ``test_lambda_function`` pins it to
the spec value so a divergence is caught in CI.

Related: ENC-ISS-390, ENC-LSN-055, ENC-TSK-I27, ENC-TSK-I28.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Configuration (mirrors recompute_governance for the shared contract)
# ---------------------------------------------------------------------------

S3_BUCKET = os.environ.get("GOVERNANCE_S3_BUCKET", "jreese-net")
S3_GOVERNANCE_PREFIX = "governance/live"
TABLE_NAME = os.environ.get("GOVERNANCE_VERSION_TABLE", "governance-version")
CANONICAL_ITEM_KEY = "governance-version-current"
REGION = os.environ.get("AWS_REGION", "us-west-2")

DRIFT_METRIC_NAMESPACE = os.environ.get("DRIFT_METRIC_NAMESPACE", "Enceladus/Governance")
DRIFT_METRIC_NAME = "GovernanceVersionDrift"
SNS_TOPIC_ARN = os.environ.get(
    "GOVERNANCE_ALERT_SNS_ARN",
    "arn:aws:sns:us-west-2:356364570033:devops-project-json-sync",
)

_s3_client = None
_ddb_client = None
_cw_client = None
_sns_client = None


def _get_s3():
    global _s3_client
    if _s3_client is None:
        import boto3
        _s3_client = boto3.client("s3", region_name=REGION)
    return _s3_client


def _get_ddb():
    global _ddb_client
    if _ddb_client is None:
        import boto3
        _ddb_client = boto3.client("dynamodb", region_name=REGION)
    return _ddb_client


def _get_cw():
    global _cw_client
    if _cw_client is None:
        import boto3
        _cw_client = boto3.client("cloudwatch", region_name=REGION)
    return _cw_client


def _get_sns():
    global _sns_client
    if _sns_client is None:
        import boto3
        _sns_client = boto3.client("sns", region_name=REGION)
    return _sns_client


# ---------------------------------------------------------------------------
# Canonical file set + §4.3 hashing — keep in sync with recompute_governance
# ---------------------------------------------------------------------------

def _s3_key_to_uri(s3_key: str) -> str:
    rel = s3_key[len(S3_GOVERNANCE_PREFIX) + 1:]
    return f"governance://{rel}"


def _list_canonical_files() -> list[tuple[str, str]]:
    """Return (governance_uri, s3_key) for all canonical files, lex-sorted by URI."""
    files: list[tuple[str, str]] = []

    agents_md = f"{S3_GOVERNANCE_PREFIX}/agents.md"
    try:
        _get_s3().head_object(Bucket=S3_BUCKET, Key=agents_md)
        files.append((_s3_key_to_uri(agents_md), agents_md))
    except Exception:
        logger.warning("agents.md not found in S3; excluding from canonical set")

    paginator = _get_s3().get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=S3_BUCKET, Prefix=f"{S3_GOVERNANCE_PREFIX}/agents/"):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            files.append((_s3_key_to_uri(key), key))

    files.sort(key=lambda t: t[0])
    return files


def _get_file_checksum(s3_key: str) -> tuple[str, str]:
    """Return (checksum_sha256_hex, s3_version_id) via GetObjectAttributes."""
    resp = _get_s3().get_object_attributes(
        Bucket=S3_BUCKET,
        Key=s3_key,
        ObjectAttributes=["Checksum"],
    )
    b64 = (resp.get("Checksum") or {}).get("ChecksumSHA256")
    if not b64:
        raise ValueError(
            f"No ChecksumSHA256 on {s3_key}. "
            "Governance uploads must carry SHA256 additional checksum."
        )
    return base64.b64decode(b64).hex(), resp.get("VersionId", "")


def _read_governance_revision(agents_md_key: str) -> str:
    resp = _get_s3().get_object(Bucket=S3_BUCKET, Key=agents_md_key)
    content = resp["Body"].read().decode("utf-8")
    m = re.search(r"(?:^|\n)governance_revision:\s*(\S+)", content)
    return m.group(1).strip() if m else "unknown"


def _compute_bundle_hash(file_entries: list[dict[str, str]]) -> str:
    """§4.3: sha256( concat(URI + \\n + hex_fingerprint + \\n) ) in lex URI order."""
    h = hashlib.sha256()
    for entry in file_entries:
        h.update(entry["uri"].encode())
        h.update(b"\n")
        h.update(entry["checksum_sha256_hex"].encode())
        h.update(b"\n")
    return h.hexdigest()


def _recompute_live_state() -> dict[str, Any]:
    """Recompute governance_hash + per-file fingerprints from current live S3."""
    canonical = _list_canonical_files()
    if not canonical:
        raise RuntimeError("Canonical governance file set is empty in live S3")

    agents_md_key = f"{S3_GOVERNANCE_PREFIX}/agents.md"
    governance_revision = _read_governance_revision(agents_md_key)

    file_entries: list[dict[str, str]] = []
    for uri, s3_key in canonical:
        checksum_hex, version_id = _get_file_checksum(s3_key)
        file_entries.append(
            {
                "uri": uri,
                "s3_key": s3_key,
                "s3_version_id": version_id,
                "checksum_sha256_hex": checksum_hex,
            }
        )

    return {
        "governance_hash": _compute_bundle_hash(file_entries),
        "governance_revision": governance_revision,
        "files": file_entries,
    }


# ---------------------------------------------------------------------------
# Canonical record read
# ---------------------------------------------------------------------------

def _read_canonical_record() -> dict[str, Any] | None:
    resp = _get_ddb().get_item(
        TableName=TABLE_NAME,
        Key={"version_id": {"S": CANONICAL_ITEM_KEY}},
        ConsistentRead=True,
    )
    item = resp.get("Item")
    if not item:
        return None
    files_raw = item.get("files", {}).get("S", "[]")
    try:
        files = json.loads(files_raw)
    except (ValueError, TypeError):
        files = []
    return {
        "governance_hash": item.get("governance_hash", {}).get("S", ""),
        "governance_revision": item.get("governance_revision", {}).get("S", ""),
        "generation": int(item.get("generation", {}).get("N", "0")),
        "files": files,
    }


# ---------------------------------------------------------------------------
# Drift comparison
# ---------------------------------------------------------------------------

def _file_fingerprints(files: list[dict[str, str]]) -> dict[str, str]:
    """Map uri -> checksum_sha256_hex for a cheap per-file comparison."""
    return {f.get("uri", ""): f.get("checksum_sha256_hex", "") for f in files}


def detect_drift() -> dict[str, Any]:
    """Compare the canonical record against freshly-recomputed live S3 state.

    Returns a result dict with ``drift`` (bool), ``reason``, and detail fields.
    A recompute failure or a missing record is treated as drift (fail-closed).
    """
    try:
        live = _recompute_live_state()
    except Exception as exc:  # recompute failure is itself a drift signal
        logger.error("[DRIFT] recompute from live S3 failed: %s", exc)
        return {
            "drift": True,
            "reason": "recompute_failure",
            "message": f"Failed to recompute governance hash from live S3: {exc}",
        }

    record = _read_canonical_record()
    if record is None:
        return {
            "drift": True,
            "reason": "record_missing",
            "message": (
                "Canonical governance-version record does not exist; run the "
                "backfill seed (ENC-TSK-I32) or check the recompute Lambda."
            ),
            "live_governance_hash": live["governance_hash"],
            "live_governance_revision": live["governance_revision"],
        }

    hash_agrees = record["governance_hash"] == live["governance_hash"]
    revision_agrees = record["governance_revision"] == live["governance_revision"]

    live_fp = _file_fingerprints(live["files"])
    record_fp = _file_fingerprints(record["files"])
    mismatched_files = sorted(
        uri
        for uri in set(live_fp) | set(record_fp)
        if live_fp.get(uri) != record_fp.get(uri)
    )

    drift = not hash_agrees or bool(mismatched_files)
    result = {
        "drift": drift,
        "reason": "hash_mismatch" if drift else "agree",
        "generation": record["generation"],
        "hash_agrees": hash_agrees,
        "revision_agrees": revision_agrees,
        "record_governance_hash": record["governance_hash"],
        "live_governance_hash": live["governance_hash"],
        "record_governance_revision": record["governance_revision"],
        "live_governance_revision": live["governance_revision"],
        "mismatched_files": mismatched_files,
    }
    if drift:
        result["message"] = (
            "Canonical governance-version record disagrees with live S3: "
            f"hash_agrees={hash_agrees}, mismatched_files={mismatched_files}."
        )
    return result


# ---------------------------------------------------------------------------
# Emit: CloudWatch metric + SNS alert
# ---------------------------------------------------------------------------

def _emit_metric(drift: bool) -> None:
    try:
        _get_cw().put_metric_data(
            Namespace=DRIFT_METRIC_NAMESPACE,
            MetricData=[
                {
                    "MetricName": DRIFT_METRIC_NAME,
                    "Value": 1.0 if drift else 0.0,
                    "Unit": "Count",
                }
            ],
        )
    except Exception as exc:  # never let telemetry failure mask the check
        logger.error("[ERROR] Failed to emit CloudWatch metric: %s", exc)


def _publish_alert(result: dict[str, Any]) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    alert = {
        "alert_type": "GOVERNANCE_VERSION_DRIFT",
        "reason": result.get("reason"),
        "message": result.get("message", "governance version drift detected"),
        "record_governance_hash": result.get("record_governance_hash"),
        "live_governance_hash": result.get("live_governance_hash"),
        "mismatched_files": result.get("mismatched_files"),
        "generation": result.get("generation"),
        "detected_at": now,
    }
    subject = f"[GOVERNANCE] Version drift detected: {result.get('reason')}"
    try:
        _get_sns().publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject[:100],
            Message=json.dumps(alert, indent=2),
            MessageAttributes={
                "alert_type": {
                    "DataType": "String",
                    "StringValue": "GOVERNANCE_VERSION_DRIFT",
                },
            },
        )
        logger.warning("[GOVERNANCE] Drift alert published: %s", result.get("reason"))
    except Exception as exc:
        logger.error("[ERROR] Failed to publish SNS drift alert: %s", exc)


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

def handler(event: dict, context: Any) -> dict[str, Any]:
    """Scheduled (or on-demand) drift check. Emits metric + alert; returns result."""
    result = detect_drift()
    drift = bool(result.get("drift"))

    _emit_metric(drift)
    if drift:
        _publish_alert(result)
        logger.warning("[GOVERNANCE] %s", result.get("message", "drift detected"))
    else:
        logger.info(
            "[GOVERNANCE] No drift: generation=%s hash=%s",
            result.get("generation"),
            str(result.get("record_governance_hash"))[:16],
        )

    logger.info("[END] Governance drift check: %s", json.dumps({k: result[k] for k in ("drift", "reason")}))
    return result
