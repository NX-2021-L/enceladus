"""id_service/lambda_function.py — Enceladus ID Service (B63 Phase 2 AC-6 / ENC-TSK-L06)

Extracts record-ID allocation OUT of the tracker_mutation monolith into a standalone,
synchronously-invoked Lambda. This service is the SOLE authority for:

  1. IAM-level isolation   — only this Lambda's role may write the tracker table's
     `counter#*` partition keys. tracker_mutation's role carries an explicit DENY on
     those keys (see infrastructure/cloudformation/02-compute.yaml TrackerMutationRole),
     forcing all counter allocation through this service.
  2. Idempotency-key contract — a client-supplied `idempotency_key` returns the SAME
     record_id on retry instead of allocating a new one. Backed by a dedicated,
     TTL'd DynamoDB table (enceladus-id-idempotency{-gamma}).
  3. Cryptographic provenance — every allocated record_id is stamped with an
     `item_id_provenance` HMAC-SHA256 signature over `record_id||created_at||record_type`,
     using a shared secret held in Secrets Manager (never hardcoded, never logged).
  4. Trust-score feedback — `record_violation` increments a per-caller-identity violation
     counter (enceladus-id-violations{-gamma}) whenever tracker_mutation's edge-layer
     guard rejects an ID_BOUNDARY_VIOLATION, and flags callers past a threshold.

Invocation: direct Lambda invoke (RequestResponse) from tracker_mutation. The event IS the
request dict (no API Gateway envelope). Returns a verdict dict: {allow, error, record_id,
item_id_provenance, ...}. This service is invoked synchronously and FAIL-CLOSED from the
caller's perspective (ENC-TSK-L06 mirrors the ENC-TSK-H46 Lifecycle Service posture) — an
ID-generation failure must reject the create, never silently fall back to a different
generation path (that would defeat the isolation property).

Environment variables:
  DYNAMODB_TABLE          default: devops-project-tracker      (counter items live here)
  IDEMPOTENCY_TABLE       default: enceladus-id-idempotency     (idempotency_key -> record_id)
  VIOLATIONS_TABLE        default: enceladus-id-violations      (caller_identity -> violation stats)
  DYNAMODB_REGION         default: us-west-2
  HMAC_SECRET_ARN         Secrets Manager ARN holding the provenance-signing shared secret.
  VIOLATION_THRESHOLD     default: 5   (violations before a caller is flagged in the verdict)
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import logging
import os
from typing import Any, Dict, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ID_SERVICE_VERSION = "1.0.0"  # ENC-TSK-L06

# DYNAMODB_TABLE (the shared tracker table) is used READ-ONLY here, solely by
# _max_existing_number's cold-start fallback scan. All counter allocation reads/writes
# go to ID_COUNTERS_TABLE, a dedicated table this Lambda's role exclusively owns (AC-0
# IAM isolation — see infrastructure/cloudformation/02-compute.yaml IdServiceRole /
# IdCountersTableAccess; TrackerMutationRole has no grant referencing that table's ARN
# anywhere, which is the AWS-native, verifiable isolation mechanism: ordinary
# resource-scoped IAM, not a same-table sort-key condition — dynamodb:LeadingKeys can
# only constrain a partition key, and project_id (the tracker table's partition key) is
# never "counter#*", so a same-table condition DENY would have been a silent no-op).
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "devops-project-tracker")
ID_COUNTERS_TABLE = os.environ.get("ID_COUNTERS_TABLE", "enceladus-id-counters")
IDEMPOTENCY_TABLE = os.environ.get("IDEMPOTENCY_TABLE", "enceladus-id-idempotency")
VIOLATIONS_TABLE = os.environ.get("VIOLATIONS_TABLE", "enceladus-id-violations")
DYNAMODB_REGION = os.environ.get("DYNAMODB_REGION", "us-west-2")
HMAC_SECRET_ARN = os.environ.get("HMAC_SECRET_ARN", "")
VIOLATION_THRESHOLD = int(os.environ.get("VIOLATION_THRESHOLD", "5"))

# Idempotency records are kept for 24h — long enough to cover realistic client retry
# windows (network blips, Lambda cold-start timeouts) without accumulating forever.
_IDEMPOTENCY_TTL_SECONDS = 24 * 60 * 60

_TRACKER_TYPE_SUFFIX = {
    "task": "TSK", "issue": "ISS", "feature": "FTR", "lesson": "LSN",
    "plan": "PLN", "generation": "GEN", "escalation": "ESC",
}

# ---------------------------------------------------------------------------
# Base-36 sequence encoding (ENC-FTR-056 / ENC-ISS-132) — reimplemented here
# rather than imported from tracker_mutation, mirroring how lifecycle_service
# owns its own copy of transition_type_matrix rather than cross-importing a
# sibling Lambda's module (each extracted service is a self-contained
# deployment unit with no shared source tree between backend/lambda/* dirs).
# ---------------------------------------------------------------------------

_BASE36_CAPACITY = 46655  # ZZZ in base-36
_BASE36_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _b36_to_str(v: int) -> str:
    r = []
    for _ in range(3):
        r.append(_BASE36_CHARS[v % 36])
        v //= 36
    return "".join(reversed(r))


def _str_to_b36(s: str) -> int:
    result = 0
    for ch in s:
        idx = _BASE36_CHARS.find(ch)
        if idx < 0:
            raise ValueError(f"Invalid base-36 character {ch!r} in sequence {s!r}")
        result = result * 36 + idx
    return result


def _is_legacy_pattern(s: str) -> bool:
    if s.isdigit():
        return True
    if len(s) == 3 and s[0].isalpha() and s[1:].isdigit():
        num = int(s[1:])
        if 1 <= num <= 99:
            return True
    return False


_EXT_B36_TO_COUNTER: dict = {}
_EXT_COUNTER_TO_B36: list = []


def _init_extended_tables():
    idx = 0
    for v in range(46656):
        s = _b36_to_str(v)
        if not _is_legacy_pattern(s):
            _EXT_COUNTER_TO_B36.append(v)
            _EXT_B36_TO_COUNTER[v] = 3574 + idx
            idx += 1


_init_extended_tables()


def _encode_base36(n: int) -> str:
    """Encode a non-negative integer into a 3-char sequence (ENC-FTR-056).

    0-999: zero-padded decimal. 1000-3573: legacy alphanumeric (A01-Z99).
    3574-46655: mapped to non-legacy 3-char base-36 strings via lookup table.
    Total capacity: 46,656 per record type per project. >=46656 -> ValueError.
    """
    if n < 0:
        raise ValueError(f"Counter must be >= 0, got {n}")
    if n > _BASE36_CAPACITY:
        raise ValueError(
            f"Base-36 capacity exhausted at counter {n}. "
            f"Maximum is {_BASE36_CAPACITY} per record type per project."
        )
    if n <= 999:
        return str(n).zfill(3)
    offset = n - 1000
    letter_index = offset // 99
    number = (offset % 99) + 1
    if letter_index <= 25:
        return chr(65 + letter_index) + str(number).zfill(2)
    ext_idx = n - 3574
    return _b36_to_str(_EXT_COUNTER_TO_B36[ext_idx])


def _decode_base36(s: str) -> int:
    """Decode a sequence string back into an integer (ENC-FTR-056)."""
    if not s:
        raise ValueError("Empty sequence")
    s = s.upper()
    if s.isdigit():
        return int(s)
    if len(s) == 3 and s[0].isalpha() and s[1:].isdigit():
        letter_index = ord(s[0]) - 65
        number = int(s[1:])
        if 0 <= letter_index <= 25 and 1 <= number <= 99:
            return 1000 + (letter_index * 99) + (number - 1)
    try:
        b36_val = _str_to_b36(s)
    except ValueError:
        raise ValueError(f"Invalid sequence: {s!r}")
    counter = _EXT_B36_TO_COUNTER.get(b36_val)
    if counter is not None:
        return counter
    raise ValueError(f"Invalid sequence: {s!r}")


_SUBTASK_SUFFIX_CAPACITY = 260  # 10 digits * 26 letters


# ---------------------------------------------------------------------------
# AWS clients (lazy, cached across warm invocations)
# ---------------------------------------------------------------------------

_ddb = None
_secretsmanager = None
_hmac_key_cache: Optional[bytes] = None


def _get_ddb():
    global _ddb
    if _ddb is None:
        _ddb = boto3.client(
            "dynamodb",
            region_name=DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _ddb


def _get_secretsmanager():
    global _secretsmanager
    if _secretsmanager is None:
        _secretsmanager = boto3.client("secretsmanager", region_name=DYNAMODB_REGION)
    return _secretsmanager


def _get_hmac_key() -> bytes:
    """Fetch the provenance-signing shared secret from Secrets Manager, cached for the
    life of the execution environment (read once at cold start / first use — a rotated
    secret takes effect on the next cold start, matching the GitHub App private-key
    caching precedent in checkout_service/lambda_function.py)."""
    global _hmac_key_cache
    if _hmac_key_cache is not None:
        return _hmac_key_cache
    if not HMAC_SECRET_ARN:
        raise RuntimeError("HMAC_SECRET_ARN not configured; cannot sign provenance.")
    resp = _get_secretsmanager().get_secret_value(SecretId=HMAC_SECRET_ARN)
    secret_string = resp.get("SecretString", "")
    # The secret may be a raw string (CFN GenerateSecretString default) or a JSON blob
    # {"hmac_key": "..."} — support both so an operator-rotated JSON-shaped secret works too.
    try:
        parsed = json.loads(secret_string)
        if isinstance(parsed, dict) and "hmac_key" in parsed:
            secret_string = parsed["hmac_key"]
    except (ValueError, TypeError):
        pass
    _hmac_key_cache = secret_string.encode("utf-8")
    return _hmac_key_cache


def _now_z() -> str:
    return dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _ser_s(val: str) -> Dict:
    return {"S": str(val)}


def _is_conditional_check_failed(exc: Exception) -> bool:
    return isinstance(exc, ClientError) and exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException"


# ---------------------------------------------------------------------------
# Provenance signing (AC-2)
# ---------------------------------------------------------------------------

def sign_provenance(record_id: str, created_at: str, record_type: str) -> str:
    """Compute the item_id_provenance HMAC-SHA256 signature over
    `record_id||created_at||record_type`, hex-encoded."""
    key = _get_hmac_key()
    message = f"{record_id}||{created_at}||{record_type}".encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify_provenance(record_id: str, created_at: str, record_type: str, provenance: str) -> bool:
    """Recompute the signature and compare in constant time. Returns False (never raises)
    on any mismatch or malformed input — callers (graph_sync, graph_query_api) treat False
    as 'log + quarantine-flag', never as a hard failure for pre-existing records."""
    if not provenance:
        return False
    try:
        expected = sign_provenance(record_id, created_at, record_type)
    except Exception:  # noqa: BLE001 — defensive: secret unavailable, etc.
        logger.exception("[ID-SERVICE] provenance verification could not compute expected signature")
        return False
    return hmac.compare_digest(expected, provenance)


# ---------------------------------------------------------------------------
# Counter allocation (AC-0 IAM isolation target). Counter items live in the DEDICATED
# ID_COUNTERS_TABLE (enceladus-id-counters{-gamma}), which only this Lambda's role has
# any grant on — see infrastructure/cloudformation/02-compute.yaml IdServiceRole
# (IdCountersTableAccess) vs TrackerMutationRole (no reference to that table's ARN at
# all). This is a deliberate departure from the pre-L06 shape, where counter items lived
# as counter#* rows inside the shared tracker table: a same-table IAM condition cannot
# achieve real isolation here (dynamodb:LeadingKeys only constrains the PARTITION key,
# and the tracker table's partition key is project_id, never "counter#*" — that lives on
# the sort key, record_id). True table separation is the correct, verifiable mechanism.
# _max_existing_number is the one exception that still reads the shared tracker table
# (read-only, TrackerReadOnlyForSeed grant) — it's the cold-start fallback that
# reconstructs a counter's correct seed value from pre-existing record IDs the first
# time each (project_id, record_type) pairing is allocated through this table.
# ---------------------------------------------------------------------------

def _max_existing_number(project_id: str, record_type: str) -> int:
    ddb = _get_ddb()
    kwargs: Dict[str, Any] = {
        "TableName": DYNAMODB_TABLE,
        "KeyConditionExpression": "project_id = :pid AND begins_with(record_id, :rtype_prefix)",
        "ExpressionAttributeValues": {
            ":pid": _ser_s(project_id),
            ":rtype_prefix": _ser_s(f"{record_type}#"),
        },
        "ProjectionExpression": "record_id",
    }
    max_num = 0
    while True:
        query_resp = ddb.query(**kwargs)
        for item in query_resp.get("Items", []):
            sk = item.get("record_id", {}).get("S", "")
            human_id = sk.split("#", 1)[1] if "#" in sk else sk
            parts = human_id.split("-")
            if len(parts) >= 3:
                try:
                    max_num = max(max_num, _decode_base36(parts[-1]))
                except ValueError:
                    pass
        last_key = query_resp.get("LastEvaluatedKey")
        if not last_key:
            break
        kwargs["ExclusiveStartKey"] = last_key
    return max_num


def _next_record_id(project_id: str, prefix: str, record_type: str) -> str:
    """Allocate the next sequential record ID using an atomic counter (ENC-FTR-056 logic,
    relocated here from tracker_mutation under ENC-TSK-L06 AC-0 IAM isolation). Counter
    item lives in ID_COUNTERS_TABLE, keyed by a single `counter_key` attribute
    (`{project_id}#{record_type}`) rather than the tracker table's project_id/record_id
    composite key — a dedicated table needs no sort key since there's exactly one item
    per counter."""
    ddb = _get_ddb()
    type_suffix = _TRACKER_TYPE_SUFFIX.get(record_type, "TSK")
    counter_key_value = f"{project_id}#{record_type}"
    counter_key = {"counter_key": _ser_s(counter_key_value)}

    counter_item = ddb.get_item(
        TableName=ID_COUNTERS_TABLE, Key=counter_key, ConsistentRead=True,
    ).get("Item")

    seed_num = 0
    if not counter_item:
        seed_num = _max_existing_number(project_id, record_type)

    now = _now_z()
    update_resp = ddb.update_item(
        TableName=ID_COUNTERS_TABLE,
        Key=counter_key,
        UpdateExpression=(
            "SET next_num = if_not_exists(next_num, :seed) + :one, "
            "updated_at = :now, "
            "created_at = if_not_exists(created_at, :now), "
            "project_id = if_not_exists(project_id, :pid), "
            "record_type = if_not_exists(record_type, :counter_type)"
        ),
        ExpressionAttributeValues={
            ":seed": {"N": str(seed_num)},
            ":one": {"N": "1"},
            ":now": _ser_s(now),
            ":pid": _ser_s(project_id),
            ":counter_type": _ser_s(record_type),
        },
        ReturnValues="UPDATED_NEW",
    )
    attrs = update_resp.get("Attributes", {})
    next_num = int(attrs.get("next_num", {"N": str(seed_num + 1)}).get("N", str(seed_num + 1)))
    return f"{prefix}-{type_suffix}-{_encode_base36(next_num)}"


def _next_subtask_suffix(project_id: str, parent_root_id: str) -> str:
    """Allocate the next sub-task suffix for a parent task (ENC-FTR-056 logic, relocated to
    ID_COUNTERS_TABLE under ENC-TSK-L06 AC-0)."""
    ddb = _get_ddb()
    counter_key_value = f"{project_id}#subtask#{parent_root_id}"
    counter_key = {"counter_key": _ser_s(counter_key_value)}
    now = _now_z()
    update_resp = ddb.update_item(
        TableName=ID_COUNTERS_TABLE,
        Key=counter_key,
        UpdateExpression=(
            "SET next_num = if_not_exists(next_num, :seed) + :one, "
            "updated_at = :now, "
            "created_at = if_not_exists(created_at, :now), "
            "project_id = if_not_exists(project_id, :pid), "
            "record_type = if_not_exists(record_type, :counter_type)"
        ),
        ExpressionAttributeValues={
            ":seed": {"N": "0"},
            ":one": {"N": "1"},
            ":now": _ser_s(now),
            ":pid": _ser_s(project_id),
            ":counter_type": _ser_s("subtask"),
        },
        ReturnValues="UPDATED_NEW",
    )
    attrs = update_resp.get("Attributes", {})
    next_num = int(attrs.get("next_num", {"N": "1"}).get("N", "1"))
    if next_num >= _SUBTASK_SUFFIX_CAPACITY:
        raise ValueError(
            f"Sub-task capacity exhausted for parent {parent_root_id} "
            f"(max {_SUBTASK_SUFFIX_CAPACITY} sub-tasks)."
        )
    digit = next_num // 26
    letter = chr(65 + (next_num % 26))
    return f"{digit}{letter}"


# ---------------------------------------------------------------------------
# Idempotency-key contract (AC-1)
# ---------------------------------------------------------------------------

def _idempotency_lookup(idempotency_key: str) -> Optional[str]:
    """Return the previously-allocated record_id for this idempotency_key, or None if
    this is the first time we've seen it (or the prior record expired via TTL)."""
    if not idempotency_key:
        return None
    ddb = _get_ddb()
    resp = ddb.get_item(
        TableName=IDEMPOTENCY_TABLE,
        Key={"idempotency_key": _ser_s(idempotency_key)},
        ConsistentRead=True,
    )
    item = resp.get("Item")
    if not item:
        return None
    return item.get("record_id", {}).get("S") or None


def _idempotency_store(idempotency_key: str, record_id: str, project_id: str, record_type: str) -> bool:
    """Conditionally store the (idempotency_key -> record_id) mapping. Returns True if this
    call won the race and stored it, False if a concurrent request already stored a
    (possibly different) mapping first — the caller should then re-read via
    _idempotency_lookup to get the winning record_id rather than using its own allocation."""
    if not idempotency_key:
        return True
    ddb = _get_ddb()
    now = _now_z()
    expires_at = int(dt.datetime.utcnow().timestamp()) + _IDEMPOTENCY_TTL_SECONDS
    try:
        ddb.put_item(
            TableName=IDEMPOTENCY_TABLE,
            Item={
                "idempotency_key": _ser_s(idempotency_key),
                "record_id": _ser_s(record_id),
                "project_id": _ser_s(project_id),
                "record_type": _ser_s(record_type),
                "created_at": _ser_s(now),
                "expires_at": {"N": str(expires_at)},
            },
            ConditionExpression="attribute_not_exists(idempotency_key)",
        )
        return True
    except ClientError as exc:
        if _is_conditional_check_failed(exc):
            return False
        raise


# ---------------------------------------------------------------------------
# Trust-score feedback loop (AC-4)
# ---------------------------------------------------------------------------

def record_violation(caller_identity: str, record_type: str = "", detail: str = "") -> Dict[str, Any]:
    """Increment the per-caller violation counter for an ID_BOUNDARY_VIOLATION rejection.

    Proportionate design (ENC-TSK-L06): a single DynamoDB item per caller_identity tracks
    violation_count + last_violation_at. When violation_count crosses VIOLATION_THRESHOLD
    (default 5), the verdict includes flagged=true so the caller (tracker_mutation, and
    later the Phase 5 observability dashboard / ENC-TSK-B66) can surface a rate-limit
    signal. This is a counter + threshold flag, not a hard block — the actual create request
    is already rejected by the edge-layer guard (AC-3); this is purely the feedback signal.
    """
    caller_identity = (caller_identity or "unknown").strip() or "unknown"
    ddb = _get_ddb()
    now = _now_z()
    update_resp = ddb.update_item(
        TableName=VIOLATIONS_TABLE,
        Key={"caller_identity": _ser_s(caller_identity)},
        UpdateExpression=(
            "SET violation_count = if_not_exists(violation_count, :zero) + :one, "
            "last_violation_at = :now, "
            "first_violation_at = if_not_exists(first_violation_at, :now), "
            "last_violation_record_type = :rtype, "
            "last_violation_detail = :detail"
        ),
        ExpressionAttributeValues={
            ":zero": {"N": "0"},
            ":one": {"N": "1"},
            ":now": _ser_s(now),
            ":rtype": _ser_s(record_type or ""),
            ":detail": _ser_s((detail or "")[:500]),
        },
        ReturnValues="UPDATED_NEW",
    )
    attrs = update_resp.get("Attributes", {})
    violation_count = int(attrs.get("violation_count", {"N": "1"}).get("N", "1"))
    flagged = violation_count >= VIOLATION_THRESHOLD
    if flagged:
        logger.warning(
            "[ID-SERVICE] caller_identity=%s crossed VIOLATION_THRESHOLD=%d (count=%d)",
            caller_identity, VIOLATION_THRESHOLD, violation_count,
        )
    return {
        "ok": True,
        "caller_identity": caller_identity,
        "violation_count": violation_count,
        "threshold": VIOLATION_THRESHOLD,
        "flagged": flagged,
    }


def get_violation_status(caller_identity: str) -> Dict[str, Any]:
    """Read-only lookup for the Phase 5 observability dashboard (ENC-TSK-B66) or any other
    caller that wants to query a caller's current violation standing without incrementing it."""
    caller_identity = (caller_identity or "").strip()
    if not caller_identity:
        return {"ok": False, "error": "caller_identity is required"}
    ddb = _get_ddb()
    resp = ddb.get_item(
        TableName=VIOLATIONS_TABLE,
        Key={"caller_identity": _ser_s(caller_identity)},
        ConsistentRead=True,
    )
    item = resp.get("Item")
    if not item:
        return {
            "ok": True, "caller_identity": caller_identity, "violation_count": 0,
            "threshold": VIOLATION_THRESHOLD, "flagged": False,
        }
    violation_count = int(item.get("violation_count", {}).get("N", "0"))
    return {
        "ok": True,
        "caller_identity": caller_identity,
        "violation_count": violation_count,
        "last_violation_at": item.get("last_violation_at", {}).get("S", ""),
        "threshold": VIOLATION_THRESHOLD,
        "flagged": violation_count >= VIOLATION_THRESHOLD,
    }


# ---------------------------------------------------------------------------
# Action handlers
# ---------------------------------------------------------------------------

def _reject(status: int, message: str, *, code: str = "INTERNAL_ERROR", retryable: bool = False, **extra) -> Dict:
    return {"allow": False, "error": {"status": status, "code": code, "message": message, **extra}, "retryable": retryable}


def allocate(req: Dict[str, Any]) -> Dict[str, Any]:
    """Allocate (or idempotently replay) a record_id, and stamp its item_id_provenance.

    Request fields:
      project_id (required), prefix (required), record_type (required),
      idempotency_key (optional) — AC-1 contract,
      is_child + parent_task_id (optional) — hierarchical sub-task allocation,
      caller_identity (optional) — attribution only, not authorization.
    """
    project_id = str(req.get("project_id") or "").strip()
    prefix = str(req.get("prefix") or "").strip()
    record_type = str(req.get("record_type") or "").strip()
    idempotency_key = str(req.get("idempotency_key") or "").strip()
    is_child = bool(req.get("is_child"))
    parent_task_id = str(req.get("parent_task_id") or "").strip()

    if not project_id or not prefix or not record_type:
        return _reject(400, "project_id, prefix, and record_type are required.", code="INVALID_INPUT")

    # AC-1: idempotency-key contract. If we've already allocated for this key, replay the
    # SAME record_id (and recompute/return its provenance) instead of minting a new one.
    if idempotency_key:
        existing = _idempotency_lookup(idempotency_key)
        if existing:
            existing_created_at = str(req.get("created_at") or _now_z())
            try:
                provenance = sign_provenance(existing, existing_created_at, record_type)
            except Exception as exc:  # noqa: BLE001
                logger.exception("[ID-SERVICE] provenance signing failed on idempotent replay")
                return _reject(503, f"Provenance signing unavailable: {exc}", code="HMAC_UNAVAILABLE", retryable=True)
            return {
                "allow": True,
                "record_id": existing,
                "item_id_provenance": provenance,
                "idempotent_replay": True,
            }

    try:
        if is_child and parent_task_id:
            parent_upper = parent_task_id.upper()
            parent_parts = parent_upper.split("-")
            parent_root = "-".join(parent_parts[:3])
            suffix = _next_subtask_suffix(project_id, parent_root)
            new_id = f"{parent_root}-{suffix}"
        else:
            new_id = _next_record_id(project_id, prefix, record_type)
    except ValueError as ve:
        return _reject(400, str(ve), code="CAPACITY_EXHAUSTED")
    except Exception as exc:  # noqa: BLE001
        logger.exception("[ID-SERVICE] allocation failed")
        return _reject(500, f"ID allocation failed: {exc}", code="INTERNAL_ERROR", retryable=True)

    created_at = str(req.get("created_at") or _now_z())
    try:
        provenance = sign_provenance(new_id, created_at, record_type)
    except Exception as exc:  # noqa: BLE001
        logger.exception("[ID-SERVICE] provenance signing failed")
        return _reject(503, f"Provenance signing unavailable: {exc}", code="HMAC_UNAVAILABLE", retryable=True)

    # Store the idempotency mapping AFTER a successful allocation. If a concurrent request
    # raced us and won, defer to their record_id (their write already went to DDB first) —
    # our own freshly-allocated new_id is simply not persisted anywhere and is discarded,
    # which is safe: no record was ever written under it (the tracker put_item that consumes
    # this response is the caller's job, still to come, and only happens for the winner).
    if idempotency_key:
        won = _idempotency_store(idempotency_key, new_id, project_id, record_type)
        if not won:
            existing = _idempotency_lookup(idempotency_key)
            if existing and existing != new_id:
                try:
                    provenance = sign_provenance(existing, created_at, record_type)
                except Exception as exc:  # noqa: BLE001
                    logger.exception("[ID-SERVICE] provenance signing failed on race-loss replay")
                    return _reject(503, f"Provenance signing unavailable: {exc}", code="HMAC_UNAVAILABLE", retryable=True)
                return {
                    "allow": True,
                    "record_id": existing,
                    "item_id_provenance": provenance,
                    "idempotent_replay": True,
                }

    return {
        "allow": True,
        "record_id": new_id,
        "item_id_provenance": provenance,
        "idempotent_replay": False,
    }


def handle_record_violation(req: Dict[str, Any]) -> Dict[str, Any]:
    caller_identity = str(req.get("caller_identity") or "").strip()
    record_type = str(req.get("record_type") or "").strip()
    detail = str(req.get("detail") or "").strip()
    result = record_violation(caller_identity, record_type, detail)
    result["allow"] = True
    return result


def handle_get_violation_status(req: Dict[str, Any]) -> Dict[str, Any]:
    caller_identity = str(req.get("caller_identity") or "").strip()
    result = get_violation_status(caller_identity)
    result["allow"] = result.get("ok", False)
    return result


def verify(req: Dict[str, Any]) -> Dict[str, Any]:
    """Recompute + compare a provenance signature (used by tests / ad-hoc verification;
    graph_sync and graph_query_api call sign_provenance/verify_provenance directly in-process
    when the HMAC secret is wired to them, but this action lets an operator or the ID Service's
    own caller verify remotely too)."""
    record_id = str(req.get("record_id") or "").strip()
    created_at = str(req.get("created_at") or "").strip()
    record_type = str(req.get("record_type") or "").strip()
    provenance = str(req.get("item_id_provenance") or "").strip()
    if not (record_id and created_at and record_type and provenance):
        return _reject(400, "record_id, created_at, record_type, and item_id_provenance are required.", code="INVALID_INPUT")
    valid = verify_provenance(record_id, created_at, record_type, provenance)
    return {"allow": True, "valid": valid}


_ACTIONS = {
    "allocate": allocate,
    "record_violation": handle_record_violation,
    "get_violation_status": handle_get_violation_status,
    "verify": verify,
    "health": lambda req: {"allow": True, "ok": True, "service": "id_service", "version": ID_SERVICE_VERSION},
}


def lambda_handler(event, context):  # noqa: ANN001
    """Direct-invoke dispatch. event = {"action": ..., ...request fields}. Returns a verdict dict
    that always includes `allow` (bool) so the FAIL-CLOSED caller convention used by
    tracker_mutation (mirroring ENC-TSK-H46 Lifecycle Service) has a single field to check.

    Defensive: any unexpected exception returns a retryable 500 verdict rather than an opaque
    Lambda platform error, so the caller's fail-closed policy resolves deterministically.
    """
    try:
        if isinstance(event, str):
            event = json.loads(event)
        action = (event.get("action") or "allocate").strip()
        handler = _ACTIONS.get(action)
        if handler is None:
            return _reject(400, f"Unknown action '{action}'. Valid: {sorted(_ACTIONS)}", code="UNKNOWN_ACTION")
        return handler(event)
    except Exception as exc:  # noqa: BLE001
        logger.exception("[ID-SERVICE] unhandled error")
        return _reject(500, f"ID Service internal error: {exc}", code="INTERNAL_ERROR", retryable=True)
