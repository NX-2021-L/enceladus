"""Recompute governance-version canonical DDB record on S3 ObjectCreated events.

ENC-TSK-I27 / ENC-FTR-116 Wave 2.

Triggered by S3 ObjectCreated on governance/live/* prefix.
Computes the §4.3 bundle root hash and writes a CAS-protected canonical record
to the governance-version DynamoDB table.

Recursion-safe: writes only to DDB, never back to governance/live/*.
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

S3_BUCKET = "jreese-net"
S3_GOVERNANCE_PREFIX = "governance/live"
TABLE_NAME = os.environ.get("GOVERNANCE_VERSION_TABLE", "governance-version")
CANONICAL_ITEM_KEY = "governance-version-current"
REGION = os.environ.get("AWS_REGION", "us-west-2")

_s3_client = None
_ddb_client = None


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


# ---------------------------------------------------------------------------
# Canonical file set helpers
# ---------------------------------------------------------------------------

def _is_canonical(s3_key: str) -> bool:
    """True if this S3 key belongs to the canonical governance file set."""
    if s3_key == f"{S3_GOVERNANCE_PREFIX}/agents.md":
        return True
    if s3_key.startswith(f"{S3_GOVERNANCE_PREFIX}/agents/"):
        return True
    return False


def _s3_key_to_uri(s3_key: str) -> str:
    """Map governance/live/<rel> → governance://<rel>."""
    rel = s3_key[len(S3_GOVERNANCE_PREFIX) + 1:]
    return f"governance://{rel}"


def _list_canonical_files() -> list[tuple[str, str]]:
    """Return (governance_uri, s3_key) pairs for all canonical files, lex-sorted by URI."""
    files: list[tuple[str, str]] = []

    agents_md = f"{S3_GOVERNANCE_PREFIX}/agents.md"
    try:
        _get_s3().head_object(Bucket=S3_BUCKET, Key=agents_md)
        files.append((_s3_key_to_uri(agents_md), agents_md))
    except Exception:
        logger.warning("agents.md not found in S3; skipping from canonical set")

    paginator = _get_s3().get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=S3_BUCKET, Prefix=f"{S3_GOVERNANCE_PREFIX}/agents/"):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            files.append((_s3_key_to_uri(key), key))

    files.sort(key=lambda t: t[0])
    return files


# ---------------------------------------------------------------------------
# Checksum + revision
# ---------------------------------------------------------------------------

def _get_file_checksum(s3_key: str) -> tuple[str, str]:
    """Return (checksum_sha256_hex, s3_version_id) via GetObjectAttributes.

    Raises ValueError if the object has no SHA256 checksum (objects uploaded
    without AdditionalChecksums will fail here intentionally — governance/live/*
    uploads are required to carry SHA256 checksums per the governance contract).
    """
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
    """Extract governance_revision: from agents.md content."""
    resp = _get_s3().get_object(Bucket=S3_BUCKET, Key=agents_md_key)
    content = resp["Body"].read().decode("utf-8")
    m = re.search(r"(?:^|\n)governance_revision:\s*(\S+)", content)
    return m.group(1).strip() if m else "unknown"


# ---------------------------------------------------------------------------
# Bundle hash — §4.3
# ---------------------------------------------------------------------------

def _compute_bundle_hash(file_entries: list[dict[str, str]]) -> str:
    """§4.3: sha256( concat(URI + \\n + hex_fingerprint + \\n) ) in lex URI order."""
    h = hashlib.sha256()
    for entry in file_entries:
        h.update(entry["uri"].encode())
        h.update(b"\n")
        h.update(entry["checksum_sha256_hex"].encode())
        h.update(b"\n")
    return h.hexdigest()


# ---------------------------------------------------------------------------
# DynamoDB helpers
# ---------------------------------------------------------------------------

def _read_current_record() -> dict[str, Any] | None:
    """Read the governance-version-current item; None if not yet created."""
    resp = _get_ddb().get_item(
        TableName=TABLE_NAME,
        Key={"version_id": {"S": CANONICAL_ITEM_KEY}},
        ConsistentRead=True,
    )
    item = resp.get("Item")
    if not item:
        return None
    return {
        "generation": int(item["generation"]["N"]),
        "cas_version": int(item["cas_version"]["N"]),
        "source_event": json.loads(item.get("source_event", {}).get("S", "{}")),
    }


def _cas_write(
    *,
    governance_revision: str,
    governance_hash: str,
    generation: int,
    file_entries: list[dict[str, str]],
    source_event: dict[str, str],
    expected_cas: int | None,
) -> bool:
    """CAS-protected PutItem. expected_cas=None means first-write (attribute_not_exists guard).

    Returns True on success, False on ConditionalCheckFailedException (lost race).
    """
    from botocore.exceptions import ClientError

    now = (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )
    item = {
        "version_id": {"S": CANONICAL_ITEM_KEY},
        "governance_revision": {"S": governance_revision},
        "governance_hash": {"S": governance_hash},
        "generation": {"N": str(generation)},
        "files": {"S": json.dumps(file_entries)},
        "source_event": {"S": json.dumps(source_event)},
        "updated_at": {"S": now},
        "cas_version": {"N": str(generation)},
    }

    try:
        if expected_cas is None:
            _get_ddb().put_item(
                TableName=TABLE_NAME,
                Item=item,
                ConditionExpression="attribute_not_exists(version_id)",
            )
        else:
            _get_ddb().put_item(
                TableName=TABLE_NAME,
                Item=item,
                ConditionExpression="cas_version = :expected",
                ExpressionAttributeValues={":expected": {"N": str(expected_cas)}},
            )
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            logger.warning("CAS race on governance-version write; this invocation yields")
            return False
        raise


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

def handler(event: dict, context: Any) -> None:
    """S3 ObjectCreated event handler."""
    records = event.get("Records", [])
    if not records:
        logger.info("No records; nothing to do")
        return

    record = records[0]
    # Cross-region relay (ENC-ISS-390 e2e): the governance bucket lives in
    # us-west-1 and cannot invoke this Lambda (us-west-2) directly, so S3
    # ObjectCreated events are fanned out through an SNS topic. SNS wraps the
    # S3 event as a JSON string in record["Sns"]["Message"]. Unwrap it so the
    # handler sees the raw S3 event shape whether delivery is direct or via SNS.
    if "Sns" in record:
        try:
            inner_records = json.loads(record["Sns"]["Message"]).get("Records", [])
        except (KeyError, ValueError, TypeError) as exc:
            logger.error("Failed to unwrap SNS-wrapped S3 event: %s", exc)
            return
        if not inner_records:
            logger.info("SNS message carried no S3 Records; nothing to do")
            return
        record = inner_records[0]
    s3_obj = record["s3"]["object"]
    trigger_key: str = s3_obj["key"]
    trigger_version_id: str = s3_obj.get("versionId", "")
    trigger_sequencer: str = s3_obj.get("sequencer", "")

    logger.info(
        "Triggered by s3://%s/%s seq=%s ver=%s",
        S3_BUCKET, trigger_key, trigger_sequencer, trigger_version_id,
    )

    if not _is_canonical(trigger_key):
        logger.info("Key %s is not in canonical set; skipping", trigger_key)
        return

    # Dedup: skip if we already processed this sequencer
    current = _read_current_record()
    if current:
        prev_seq = current.get("source_event", {}).get("s3_sequencer", "")
        if prev_seq and prev_seq == trigger_sequencer:
            logger.info("Sequencer %s already processed; dedup skip", trigger_sequencer)
            return
        next_generation = current["generation"] + 1
        expected_cas: int | None = current["cas_version"]
    else:
        next_generation = 1
        expected_cas = None

    canonical = _list_canonical_files()
    if not canonical:
        logger.error("Canonical file set is empty; refusing to write empty hash")
        return

    agents_md_key = f"{S3_GOVERNANCE_PREFIX}/agents.md"
    governance_revision = _read_governance_revision(agents_md_key)

    file_entries: list[dict[str, str]] = []
    for uri, s3_key in canonical:
        checksum_hex, vid = _get_file_checksum(s3_key)
        file_entries.append(
            {
                "uri": uri,
                "s3_key": s3_key,
                "s3_version_id": vid,
                "checksum_sha256_hex": checksum_hex,
            }
        )

    governance_hash = _compute_bundle_hash(file_entries)
    source_event = {
        "s3_sequencer": trigger_sequencer,
        "trigger_s3_key": trigger_key,
        "trigger_version_id": trigger_version_id,
    }

    logger.info(
        "Writing generation=%d hash=%s... revision=%s files=%d",
        next_generation, governance_hash[:16], governance_revision, len(file_entries),
    )

    success = _cas_write(
        governance_revision=governance_revision,
        governance_hash=governance_hash,
        generation=next_generation,
        file_entries=file_entries,
        source_event=source_event,
        expected_cas=expected_cas,
    )

    if success:
        logger.info(
            "governance-version-current updated: generation=%d hash=%s",
            next_generation, governance_hash,
        )
    else:
        logger.info("CAS write skipped (lost race); another invocation updated the record")
