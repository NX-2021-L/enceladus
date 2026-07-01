"""agent_id_alloc.py — Server-side identity minting for ENC-SES / ENC-AGT (ENC-TSK-I37).

Agent ID v3 (ENC-FTR-117). Allocates two governed identity primitives on the existing
v3 stack, fronted by coordination_api (no new service — DOC-BADA8D801099 §4 Track A):

  * ENC-SES-NNN — the session. Unique, ephemeral, monotonic single-assignment: a session
    id minted once is never reissued (sessions retire, they do not recycle). Persisted to
    the session-allocation store (AGENT_SESSIONS_TABLE), keyed by ``session_id``.
  * ENC-AGT-NNN — the agent type. A durable directory entry for one surface-and-model
    tuple. Persisted to the agent-type directory (AGENT_TYPES_TABLE), keyed by
    ``agent_type_id``.

This module REUSES tracker_mutation's minting discipline (the same pattern already present
in lambda_function.py:_next_tracker_sequence): server-only allocation, a monotonic atomic
counter (DynamoDB UpdateItem ``if_not_exists(next_num,:seed) + :one``), format-enforced
base-36 ids, and a forbidden-field guard so callers can NEVER supply an id (ENC-TSK-B99 /
ENC-ISS-132). It does NOT import tracker_mutation (separate Lambda package) — the discipline
is replicated.

BUILD-ONCE GATE (DOC-05C45B438FC1). The persisted item shapes below are deliberately
VALUE-IDENTICAL to the intended v4 node property sets so that v4 promotion is a backfill,
not a reshape (ENC-TSK-I37 AC#3, elevated to a binding release gate):

    SES node properties:  agent_type_id, parent_session_id, runtime, created_at,
                          claimed_at, status        (key: session_id = ENC-SES-NNN)
    AGT node properties:  surface, model, cost_tier, status, usage_count
                                                     (key: agent_type_id = ENC-AGT-NNN)

The ENC-SES / ENC-AGT id-spaces are minted identically in v3 and v4 (``encode_seq`` is the
canonical encoder both tracks share). At v4 cutover, v4 reads and backfills these same
rows; node selection filters out the reserved ``counter#`` sentinel rows.

Scope (ENC-TSK-I37): provisioning + minting primitives only. The ``coordination(action=
agent.*)`` MCP surface is ENC-TSK-I38; the checkout active_agent_session_id value-swap is
ENC-TSK-I40. The allocator is dormant until I38 wires an invocation path.
"""
from __future__ import annotations

import datetime as dt
import json
import uuid
from typing import Any, Dict, List, Mapping, Optional

from botocore.exceptions import BotoCoreError, ClientError

from config import (
    AGENT_CREDENTIALS_TABLE,
    AGENT_SESSIONS_IDLE_THRESHOLD_SECONDS,
    AGENT_SESSIONS_TABLE,
    AGENT_TYPES_TABLE,
    logger,
)
from aws_clients import _get_ddb
from serialization import _deserialize, _now_z, _serialize

# Shared timestamp format — identical to serialization._now_z(); session timestamps
# (created_at / claimed_at) are written with this format, so the idle-sweep renders its
# cutoff the same way and compares lexicographically (a correct chronological compare).
_TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

__all__ = [
    "SESSION_ID_PREFIX",
    "AGENT_TYPE_ID_PREFIX",
    "SESSION_STATUSES",
    "AGENT_TYPE_STATUSES",
    "CREDENTIAL_STATUSES",
    "CREDENTIAL_ID_PREFIX",
    "SESSION_NODE_PROPERTIES",
    "AGENT_TYPE_NODE_PROPERTIES",
    "CREDENTIAL_NODE_PROPERTIES",
    "encode_seq",
    "mint_session_id",
    "mint_agent_type_id",
    "mint_credential_id",
    "get_session",
    "get_agent_type",
    "get_credential",
    "claim_session",
    "retire_session",
    "issue_credential",
    "rotate_credential",
    "revoke_credential",
    "sweep_idle_sessions",
    "list_sessions",
    "list_agent_types",
    "list_credentials",
    "find_agent_type",
    "IdAllocationError",
    "CallerSuppliedIdError",
]

# ---------------------------------------------------------------------------
# Format constants — the shared v3/v4 id-space (the migration seam)
# ---------------------------------------------------------------------------
SESSION_ID_PREFIX = "ENC-SES"
AGENT_TYPE_ID_PREFIX = "ENC-AGT"
# ENC-TSK-J04 / ENC-FTR-074 Ph3: credential ids are opaque uuid4 hex (CRED-<32hex>).
# Unlike ENC-SES/ENC-AGT (monotonic, human-legible, directory-ordered), a credential id
# is a secret-adjacent handle whose value must not encode issuance order — so it is minted
# from uuid4, not the shared base-36 counter. Still server-only (forbidden-field guarded).
CREDENTIAL_ID_PREFIX = "CRED"

# Reserved partition-key sentinels for the per-table monotonic counters. These rows
# coexist with node rows in the same table (tracker_mutation discipline) and are excluded
# from v4 node backfill by filtering keys that begin with "counter#".
_SESSION_COUNTER_KEY = "counter#ENC-SES"
_AGENT_TYPE_COUNTER_KEY = "counter#ENC-AGT"

_SEQ_MIN_WIDTH = 3
_BASE36_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_MINT_MAX_ATTEMPTS = 8

# Status vocabularies. SES lifecycle: allocated -> claimed -> retired (pre-allocate/claim
# flow); a self-allocated session is minted directly as claimed. AGT lifecycle: active ->
# deprecated (when a model is superseded). v4 inherits these vocabularies verbatim.
SESSION_STATUSES = ("allocated", "claimed", "retired")
AGENT_TYPE_STATUSES = ("active", "deprecated")
# CRED lifecycle: active -> revoked (terminal). Rotation issues a NEW active credential
# whose rotated_from points at the parent; the parent is then revoked (reason='rotated').
CREDENTIAL_STATUSES = ("active", "revoked")

# The exact persisted property sets (excluding the partition key). Kept as module
# constants so tests and v4 backfill can assert value-identity against them.
SESSION_NODE_PROPERTIES = (
    "agent_type_id",
    "parent_session_id",
    "runtime",
    "created_at",
    "claimed_at",
    "status",
)
AGENT_TYPE_NODE_PROPERTIES = (
    "surface",
    "model",
    "cost_tier",
    "status",
    "usage_count",
)
# CRED node properties (excluding the partition key credential_id). Value-identical to the
# intended :AgentCredential Neo4j node shape (graph_sync AGENT_NODE_PROPERTIES).
CREDENTIAL_NODE_PROPERTIES = (
    "agent_identity_id",
    "issued_at",
    "status",
    "revoked_at",
    "revoked_reason",
    "rotated_from",
)


class IdAllocationError(RuntimeError):
    """Raised when an id could not be allocated (counter or put failure after retries)."""


class CallerSuppliedIdError(ValueError):
    """Raised when a caller attempts to supply an identity id (ENC-TSK-B99 boundary)."""


# ---------------------------------------------------------------------------
# Encoding — clean, monotonic, unbounded base-36 (ENC-FTR-056 discipline)
# ---------------------------------------------------------------------------
def encode_seq(counter: int) -> str:
    """Encode a positive counter into the canonical base-36 sequence string.

    Zero-padded to a minimum of 3 chars (``1`` -> ``001``); grows beyond 3 chars naturally
    past ``ZZZ`` (46655 -> ``1000``). Order-preserving and a bijection from counter to
    string, so the counter's monotonic single-assignment carries to the id. This is the
    canonical encoder shared by v3 and v4 — do not fork it.
    """
    if not isinstance(counter, int) or isinstance(counter, bool):
        raise ValueError(f"counter must be an int, got {type(counter).__name__}")
    if counter < 1:
        raise ValueError(f"counter must be >= 1, got {counter}")
    digits = ""
    value = counter
    while value:
        value, remainder = divmod(value, 36)
        digits = _BASE36_ALPHABET[remainder] + digits
    return digits.rjust(_SEQ_MIN_WIDTH, "0")


# ---------------------------------------------------------------------------
# Forbidden-field guard — callers never supply an id (ENC-TSK-B99 / ENC-ISS-132)
# ---------------------------------------------------------------------------
def _assert_no_caller_id(payload: Optional[Mapping[str, Any]], id_field: str) -> None:
    """Reject any caller-supplied identity id. Mirrors tracker_mutation's reserved-field
    guard (lambda_function.py:2032): record IDs are generated server-side only."""
    if payload and payload.get(id_field):
        raise CallerSuppliedIdError(
            f"Field '{id_field}' must not be provided — identity ids are minted "
            f"server-side (ENC-TSK-B99)."
        )


# ---------------------------------------------------------------------------
# Monotonic atomic counter (DynamoDB UpdateItem ADD discipline)
# ---------------------------------------------------------------------------
def _next_seq(table_name: str, key_attr: str, counter_key: str) -> int:
    """Atomically allocate the next sequence number for an id-space.

    The counter row is keyed by a reserved ``counter#`` sentinel in the same table as the
    nodes (tracker_mutation pattern). ``if_not_exists(next_num, :zero) + :one`` makes the
    first allocation 1 and every subsequent allocation strictly greater — the row is never
    decremented and ids are never reissued (monotonic single-assignment).
    """
    ddb = _get_ddb()
    try:
        resp = ddb.update_item(
            TableName=table_name,
            Key={key_attr: _serialize(counter_key)},
            UpdateExpression=(
                "SET next_num = if_not_exists(next_num, :zero) + :one, "
                "record_kind = if_not_exists(record_kind, :kind), "
                "updated_at = :now"
            ),
            ExpressionAttributeValues={
                ":zero": _serialize(0),
                ":one": _serialize(1),
                ":kind": _serialize("counter"),
                ":now": _serialize(_now_z()),
            },
            ReturnValues="UPDATED_NEW",
        )
    except (BotoCoreError, ClientError) as exc:
        raise IdAllocationError(f"Failed allocating sequence on {table_name}: {exc}") from exc

    try:
        return int(resp["Attributes"]["next_num"]["N"])
    except (KeyError, TypeError, ValueError) as exc:
        raise IdAllocationError(
            f"Counter on {table_name} returned no usable next_num: {resp!r}"
        ) from exc


def _put_node(table_name: str, key_attr: str, item: Dict[str, Any]) -> None:
    """Conditional put guarding against overwriting an existing node row."""
    _get_ddb().put_item(
        TableName=table_name,
        Item={k: _serialize(v) for k, v in item.items()},
        ConditionExpression=f"attribute_not_exists({key_attr})",
    )


# ---------------------------------------------------------------------------
# Session minting — ENC-SES-NNN
# ---------------------------------------------------------------------------
def mint_session_id(
    *,
    agent_type_id: str,
    runtime: str,
    parent_session_id: str = "root",
    status: str = "allocated",
    claimed_at: str = "",
    credential_id: str = "",
    caller_payload: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Mint a server-allocated ENC-SES-NNN and persist the session node. Returns the
    persisted item (including the minted ``session_id``). The caller never supplies the id.

    ``status`` defaults to ``allocated`` (the pre-allocate/claim flow for a dispatched
    session); pass ``claimed`` for a self-allocating root/ad-hoc session, in which case
    ``claimed_at`` defaults to mint time.

    ``credential_id`` (ENC-TSK-J04) optionally binds the session to the ENC-CRED it
    authenticated with. It is written ONLY when provided, so the frozen value-identity
    shape (``SESSION_NODE_PROPERTIES``) is preserved for the credential-less path; the
    revoke cascade (``revoke_credential``) reaps sessions carrying a bound credential_id.
    """
    _assert_no_caller_id(caller_payload, "session_id")
    if status not in SESSION_STATUSES:
        raise ValueError(f"status must be one of {SESSION_STATUSES}, got {status!r}")
    if not agent_type_id:
        raise ValueError("agent_type_id is required to mint a session")

    # ENC-TSK-J43: when a session is bound to a credential, that credential must exist and
    # be active at mint time. Binding to a missing/revoked credential is rejected so the
    # revoke cascade's invariant holds (a live session's bound credential is always live).
    if credential_id:
        bound = get_credential(credential_id)
        if bound is None:
            raise ValueError(f"credential_id {credential_id!r} not found")
        if bound.get("status") != "active":
            raise ValueError(
                f"credential_id {credential_id!r} is not active "
                f"(status={bound.get('status')!r})"
            )

    now = _now_z()
    resolved_claimed_at = claimed_at or (now if status == "claimed" else "")

    last_exc: Optional[Exception] = None
    for _ in range(_MINT_MAX_ATTEMPTS):
        seq = _next_seq(AGENT_SESSIONS_TABLE, "session_id", _SESSION_COUNTER_KEY)
        session_id = f"{SESSION_ID_PREFIX}-{encode_seq(seq)}"
        item: Dict[str, Any] = {
            "session_id": session_id,
            "agent_type_id": agent_type_id,
            "parent_session_id": parent_session_id or "root",
            "runtime": runtime,
            "created_at": now,
            "claimed_at": resolved_claimed_at,
            "status": status,
        }
        if credential_id:
            item["credential_id"] = credential_id
        try:
            _put_node(AGENT_SESSIONS_TABLE, "session_id", item)
            logger.info("[INFO] Minted session id %s (agent_type=%s)", session_id, agent_type_id)
            return item
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                last_exc = exc
                continue  # extraordinarily rare: counter raced an out-of-band write — retry
            raise
    raise IdAllocationError(
        f"Failed minting session id after {_MINT_MAX_ATTEMPTS} attempts: {last_exc}"
    )


# ---------------------------------------------------------------------------
# Agent-type minting — ENC-AGT-NNN
# ---------------------------------------------------------------------------
def mint_agent_type_id(
    *,
    surface: str,
    model: str,
    cost_tier: str,
    status: str = "active",
    usage_count: int = 0,
    caller_payload: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Mint a server-allocated ENC-AGT-NNN and persist the agent-type directory node.
    Returns the persisted item (including the minted ``agent_type_id``). The caller never
    supplies the id."""
    _assert_no_caller_id(caller_payload, "agent_type_id")
    if status not in AGENT_TYPE_STATUSES:
        raise ValueError(f"status must be one of {AGENT_TYPE_STATUSES}, got {status!r}")
    if not (surface and model and cost_tier):
        raise ValueError("surface, model, and cost_tier are required to mint an agent type")
    if not isinstance(usage_count, int) or isinstance(usage_count, bool) or usage_count < 0:
        raise ValueError(f"usage_count must be a non-negative int, got {usage_count!r}")

    last_exc: Optional[Exception] = None
    for _ in range(_MINT_MAX_ATTEMPTS):
        seq = _next_seq(AGENT_TYPES_TABLE, "agent_type_id", _AGENT_TYPE_COUNTER_KEY)
        agent_type_id = f"{AGENT_TYPE_ID_PREFIX}-{encode_seq(seq)}"
        item: Dict[str, Any] = {
            "agent_type_id": agent_type_id,
            "surface": surface,
            "model": model,
            "cost_tier": cost_tier,
            "status": status,
            "usage_count": usage_count,
        }
        try:
            _put_node(AGENT_TYPES_TABLE, "agent_type_id", item)
            logger.info("[INFO] Minted agent type id %s (%s / %s)", agent_type_id, surface, model)
            return item
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                last_exc = exc
                continue
            raise
    raise IdAllocationError(
        f"Failed minting agent type id after {_MINT_MAX_ATTEMPTS} attempts: {last_exc}"
    )


# ---------------------------------------------------------------------------
# Read helpers (server-side verification; full agent.list surface is ENC-TSK-I38)
# ---------------------------------------------------------------------------
def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    """Return the session node for ``session_id``, or None if absent."""
    raw = _get_ddb().get_item(
        TableName=AGENT_SESSIONS_TABLE,
        Key={"session_id": _serialize(session_id)},
        ConsistentRead=True,
    ).get("Item")
    return _deserialize(raw) if raw else None


def get_agent_type(agent_type_id: str) -> Optional[Dict[str, Any]]:
    """Return the agent-type node for ``agent_type_id``, or None if absent."""
    raw = _get_ddb().get_item(
        TableName=AGENT_TYPES_TABLE,
        Key={"agent_type_id": _serialize(agent_type_id)},
        ConsistentRead=True,
    ).get("Item")
    return _deserialize(raw) if raw else None


# ---------------------------------------------------------------------------
# Session lifecycle mutations — ENC-TSK-I38
# ---------------------------------------------------------------------------

def claim_session(
    session_id: str,
    *,
    expected_agent_type_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Flip an allocated session to claimed (allocated → claimed, append-only).

    Validates: session exists, current status is 'allocated', and optionally
    enforces parent-lineage by comparing agent_type_id against
    ``expected_agent_type_id``. Returns the updated session item.

    Raises ValueError when the session is missing, already past 'allocated',
    or when the agent_type_id lineage check fails.
    """
    if not session_id:
        raise ValueError("session_id is required")

    ddb = _get_ddb()
    now = _now_z()
    condition = "#st = :allocated"
    expr_names: Dict[str, str] = {"#st": "status"}
    expr_values: Dict[str, Any] = {
        ":claimed": _serialize("claimed"),
        ":allocated": _serialize("allocated"),
        ":now": _serialize(now),
    }
    if expected_agent_type_id:
        condition = "#st = :allocated AND agent_type_id = :exp_agt"
        expr_values[":exp_agt"] = _serialize(expected_agent_type_id)

    try:
        resp = ddb.update_item(
            TableName=AGENT_SESSIONS_TABLE,
            Key={"session_id": _serialize(session_id)},
            UpdateExpression="SET #st = :claimed, claimed_at = :now",
            ConditionExpression=condition,
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values,
            ReturnValues="ALL_NEW",
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            existing = get_session(session_id)
            if existing is None:
                raise ValueError(f"Session {session_id!r} not found") from exc
            if existing.get("status") != "allocated":
                raise ValueError(
                    f"Session {session_id!r} is not claimable: status={existing.get('status')!r}"
                ) from exc
            raise ValueError(
                f"Session {session_id!r} agent_type_id lineage mismatch "
                f"(expected {expected_agent_type_id!r})"
            ) from exc
        raise

    updated = _deserialize(resp.get("Attributes", {}))
    logger.info("[INFO] Claimed session %s", session_id)
    return updated


def retire_session(session_id: str) -> Dict[str, Any]:
    """Flip a session to retired from any live state (allocated or claimed → retired).

    Append-only: once retired a session cannot be un-retired. Returns the
    updated session item.

    Raises ValueError when the session is missing or already retired.
    """
    if not session_id:
        raise ValueError("session_id is required")

    ddb = _get_ddb()
    try:
        resp = ddb.update_item(
            TableName=AGENT_SESSIONS_TABLE,
            Key={"session_id": _serialize(session_id)},
            UpdateExpression="SET #st = :retired",
            ConditionExpression="#st = :allocated OR #st = :claimed",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":retired": _serialize("retired"),
                ":allocated": _serialize("allocated"),
                ":claimed": _serialize("claimed"),
            },
            ReturnValues="ALL_NEW",
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            existing = get_session(session_id)
            if existing is None:
                raise ValueError(f"Session {session_id!r} not found") from exc
            if existing.get("status") == "retired":
                raise ValueError(f"Session {session_id!r} is already retired") from exc
            raise ValueError(
                f"Session {session_id!r} cannot be retired from status={existing.get('status')!r}"
            ) from exc
        raise

    updated = _deserialize(resp.get("Attributes", {}))
    logger.info("[INFO] Retired session %s", session_id)
    return updated


# ---------------------------------------------------------------------------
# Idle-sweep backstop — ENC-TSK-I71 (ENC-FTR-117 AC#8)
# ---------------------------------------------------------------------------

def _idle_reference(item: Mapping[str, Any]) -> str:
    """Return the timestamp marking a session's last lifecycle transition.

    For a claimed session that is ``claimed_at``; for an allocated (never-claimed) session
    it is ``created_at``. There is no separate heartbeat attribute, so the most recent
    lifecycle event stands in as the clock against which idleness is measured.
    """
    return str(item.get("claimed_at") or item.get("created_at") or "")


def sweep_idle_sessions(
    *,
    idle_threshold_seconds: int = AGENT_SESSIONS_IDLE_THRESHOLD_SECONDS,
    now: Optional[dt.datetime] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Reap abandoned sessions: flip live sessions (allocated/claimed) idle past the
    threshold to ``retired``.

    This is the TTL idle-sweep backstop of ENC-FTR-117 AC#8 — the third leg after
    append-only storage (ENC-TSK-I37) and explicit ``agent.retire`` (ENC-TSK-I38). It is a
    backstop for sessions whose agent died or hung without calling ``agent.retire``.

    Idleness is measured from the session's last lifecycle transition (``_idle_reference``):
    a session is a candidate when that timestamp is strictly older than
    ``now - idle_threshold_seconds``.

    Append-only and idempotent by construction:

      * Each candidate is retired through ``retire_session`` — the SAME conditional
        ``UpdateItem`` (``#st = :allocated OR #st = :claimed`` -> ``retired``) used by
        ``agent.retire``. Nothing is ever deleted; this is deliberately NOT DynamoDB native
        TTL (native TTL hard-deletes and would violate the append-only retire model).
      * Already-retired sessions never enter the candidate set (the scan filters to live
        statuses), so re-running produces no duplicate state changes.
      * A candidate concurrently retired between scan and update fails the conditional check
        and is recorded under ``skipped`` rather than erroring the whole sweep.

    Args:
        idle_threshold_seconds: age past which a live session is considered abandoned.
        now: reference instant (defaults to current UTC); injectable for testing.
        dry_run: when True, report candidates without mutating any session.

    Returns a summary dict (counts + ids).
    """
    if isinstance(idle_threshold_seconds, bool) or not isinstance(idle_threshold_seconds, int):
        raise ValueError(
            f"idle_threshold_seconds must be an int, got {type(idle_threshold_seconds).__name__}"
        )
    if idle_threshold_seconds < 0:
        raise ValueError(f"idle_threshold_seconds must be >= 0, got {idle_threshold_seconds}")

    now_dt = now or dt.datetime.now(dt.timezone.utc)
    cutoff = (now_dt - dt.timedelta(seconds=idle_threshold_seconds)).strftime(_TS_FORMAT)

    ddb = _get_ddb()
    scan_kwargs: Dict[str, Any] = {
        "TableName": AGENT_SESSIONS_TABLE,
        "FilterExpression": (
            "NOT begins_with(session_id, :ctr_pfx) "
            "AND (#st = :allocated OR #st = :claimed)"
        ),
        "ExpressionAttributeNames": {"#st": "status"},
        "ExpressionAttributeValues": {
            ":ctr_pfx": _serialize("counter#"),
            ":allocated": _serialize("allocated"),
            ":claimed": _serialize("claimed"),
        },
    }

    scanned_live = 0
    candidate_ids: List[str] = []
    scan = ddb.scan(**scan_kwargs)
    while True:
        for raw in scan.get("Items", []):
            item = _deserialize(raw)
            scanned_live += 1
            ref = _idle_reference(item)
            if ref and ref < cutoff:
                candidate_ids.append(item["session_id"])
        last_key = scan.get("LastEvaluatedKey")
        if not last_key:
            break
        scan = ddb.scan(ExclusiveStartKey=last_key, **scan_kwargs)

    retired: List[str] = []
    skipped: List[Dict[str, str]] = []
    if not dry_run:
        for sid in candidate_ids:
            try:
                retire_session(sid)
                retired.append(sid)
            except ValueError as exc:
                # Concurrently retired/transitioned between scan and update — idempotent skip.
                skipped.append({"session_id": sid, "reason": str(exc)})

    summary: Dict[str, Any] = {
        "enabled": True,
        "dry_run": dry_run,
        "idle_threshold_seconds": idle_threshold_seconds,
        "cutoff": cutoff,
        "scanned_live": scanned_live,
        "candidate_count": len(candidate_ids),
        "candidate_ids": candidate_ids,
        "retired_count": len(retired),
        "retired": retired,
        "skipped_count": len(skipped),
        "skipped": skipped,
    }
    logger.info("[INFO] Agent-session idle-sweep: %s", json.dumps(summary, default=str))
    return summary


# ---------------------------------------------------------------------------
# Directory reads — paginated scans (ENC-TSK-I38)
# ---------------------------------------------------------------------------

def list_sessions(
    *,
    status: Optional[str] = None,
    agent_type_id: Optional[str] = None,
    credential_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return all session nodes, excluding counter# sentinel rows.

    Accepts optional ``status``, ``agent_type_id`` and ``credential_id`` filters. The
    ``credential_id`` filter (ENC-TSK-J04) powers the revoke cascade's session reap.
    Results are returned in DynamoDB scan order (unordered within a page).
    """
    ddb = _get_ddb()
    filter_parts = ["NOT begins_with(session_id, :ctr_pfx)"]
    expr_names: Dict[str, str] = {}
    expr_values: Dict[str, Any] = {":ctr_pfx": _serialize("counter#")}

    if status:
        filter_parts.append("#st = :status")
        expr_names["#st"] = "status"
        expr_values[":status"] = _serialize(status)
    if agent_type_id:
        filter_parts.append("agent_type_id = :agt")
        expr_values[":agt"] = _serialize(agent_type_id)
    if credential_id:
        filter_parts.append("credential_id = :cred")
        expr_values[":cred"] = _serialize(credential_id)

    kwargs: Dict[str, Any] = {
        "TableName": AGENT_SESSIONS_TABLE,
        "FilterExpression": " AND ".join(filter_parts),
        "ExpressionAttributeValues": expr_values,
    }
    if expr_names:
        kwargs["ExpressionAttributeNames"] = expr_names

    items: List[Dict[str, Any]] = []
    scan = ddb.scan(**kwargs)
    items.extend([_deserialize(r) for r in scan.get("Items", [])])
    while scan.get("LastEvaluatedKey"):
        scan = ddb.scan(**kwargs, ExclusiveStartKey=scan["LastEvaluatedKey"])
        items.extend([_deserialize(r) for r in scan.get("Items", [])])
    return items


def list_agent_types(*, status: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return all agent-type nodes, excluding counter# sentinel rows.

    Accepts an optional ``status`` filter (``"active"`` or ``"deprecated"``).
    """
    ddb = _get_ddb()
    filter_parts = ["NOT begins_with(agent_type_id, :ctr_pfx)"]
    expr_names: Dict[str, str] = {}
    expr_values: Dict[str, Any] = {":ctr_pfx": _serialize("counter#")}

    if status:
        filter_parts.append("#st = :status")
        expr_names["#st"] = "status"
        expr_values[":status"] = _serialize(status)

    kwargs: Dict[str, Any] = {
        "TableName": AGENT_TYPES_TABLE,
        "FilterExpression": " AND ".join(filter_parts),
        "ExpressionAttributeValues": expr_values,
    }
    if expr_names:
        kwargs["ExpressionAttributeNames"] = expr_names

    items: List[Dict[str, Any]] = []
    scan = ddb.scan(**kwargs)
    items.extend([_deserialize(r) for r in scan.get("Items", [])])
    while scan.get("LastEvaluatedKey"):
        scan = ddb.scan(**kwargs, ExclusiveStartKey=scan["LastEvaluatedKey"])
        items.extend([_deserialize(r) for r in scan.get("Items", [])])
    return items


def find_agent_type(*, surface: str, model: str) -> Optional[Dict[str, Any]]:
    """Scan AGENT_TYPES_TABLE for a node matching surface + model.

    Returns the first active match (preferring active over deprecated), or
    None if no match exists. Used by agent.type.register for idempotency:
    if a type already exists for this surface/model pair, return it rather
    than minting a duplicate.
    """
    ddb = _get_ddb()
    scan = ddb.scan(
        TableName=AGENT_TYPES_TABLE,
        FilterExpression=(
            "surface = :surface AND model = :model "
            "AND NOT begins_with(agent_type_id, :ctr_pfx)"
        ),
        ExpressionAttributeValues={
            ":surface": _serialize(surface),
            ":model": _serialize(model),
            ":ctr_pfx": _serialize("counter#"),
        },
    )
    items = [_deserialize(r) for r in scan.get("Items", [])]
    active = [i for i in items if i.get("status") == "active"]
    return active[0] if active else (items[0] if items else None)


# ---------------------------------------------------------------------------
# Agent-credential lifecycle — CRED-<uuid4hex> (ENC-TSK-J04 / ENC-FTR-074 Ph3)
# ---------------------------------------------------------------------------
#
# A credential is the durable, revocable link between an agent IDENTITY (ENC-AGT-NNN)
# and the M2M auth material minted for it (ENC-FTR-074 Ph1/Ph2 dual-client Cognito).
# It rides the SAME async DynamoDB Streams -> EventBridge Pipe -> SQS -> graph_sync path
# as sessions/types; graph_sync projects :AgentCredential nodes and OWNED_BY / DERIVED_FROM
# edges. There is NO synchronous Neo4j write here — the graph is a derived read-index.
#
# Lifecycle:  issue -> (rotate)* -> revoke
#   * issue_credential:  active credential OWNED_BY an identity.
#   * rotate_credential: issue a new active credential (rotated_from=parent) then revoke the
#     parent with reason='rotated'. Graph gets a DERIVED_FROM edge child -> parent.
#   * revoke_credential: terminal flip to 'revoked'; CASCADES (see below).


def get_credential(credential_id: str) -> Optional[Dict[str, Any]]:
    """Return the credential node for ``credential_id``, or None if absent."""
    raw = _get_ddb().get_item(
        TableName=AGENT_CREDENTIALS_TABLE,
        Key={"credential_id": _serialize(credential_id)},
        ConsistentRead=True,
    ).get("Item")
    return _deserialize(raw) if raw else None


def mint_credential_id(caller_payload: Optional[Mapping[str, Any]] = None) -> str:
    """Mint an opaque server-only credential id (``CRED-<32 hex>``).

    Unlike ENC-SES / ENC-AGT, credential ids do NOT use the shared monotonic base-36
    counter — a credential handle is secret-adjacent and must not encode issuance order.
    uuid4 gives a collision-free, order-free id. Server-only: callers may never supply it
    (forbidden-field guard, mirroring the ENC-TSK-B99 boundary).
    """
    _assert_no_caller_id(caller_payload, "credential_id")
    return f"{CREDENTIAL_ID_PREFIX}-{uuid.uuid4().hex}"


def issue_credential(
    *,
    agent_identity_id: str,
    rotated_from: str = "",
    caller_payload: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Issue a new active credential owned by ``agent_identity_id`` and persist it.

    ``rotated_from`` (optional) is the parent credential id when this credential is the
    product of a rotation; it drives the graph DERIVED_FROM edge (child -> parent). The
    caller never supplies the credential id. Returns the persisted item.
    """
    _assert_no_caller_id(caller_payload, "credential_id")
    if not agent_identity_id:
        raise ValueError("agent_identity_id is required to issue a credential")
    if not str(agent_identity_id).startswith(AGENT_TYPE_ID_PREFIX):
        raise ValueError(
            f"agent_identity_id must be an {AGENT_TYPE_ID_PREFIX}-NNN id, got {agent_identity_id!r}"
        )

    now = _now_z()
    last_exc: Optional[Exception] = None
    for _ in range(_MINT_MAX_ATTEMPTS):
        credential_id = mint_credential_id()
        item: Dict[str, Any] = {
            "credential_id": credential_id,
            "agent_identity_id": agent_identity_id,
            "issued_at": now,
            "status": "active",
            "revoked_at": "",
            "revoked_reason": "",
            "rotated_from": rotated_from or "",
        }
        try:
            _put_node(AGENT_CREDENTIALS_TABLE, "credential_id", item)
            logger.info(
                "[INFO] Issued credential %s (identity=%s, rotated_from=%s)",
                credential_id, agent_identity_id, rotated_from or "-",
            )
            return item
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                last_exc = exc
                continue  # uuid4 collision is astronomically unlikely — retry regardless
            raise
    raise IdAllocationError(
        f"Failed minting credential id after {_MINT_MAX_ATTEMPTS} attempts: {last_exc}"
    )


def rotate_credential(
    credential_id: str,
    *,
    caller_payload: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Rotate an active credential: issue a successor then revoke the parent.

    Returns ``{"new_credential": {...}, "revoked_parent": {...}}``. The successor's
    ``rotated_from`` points at ``credential_id`` (drives the graph DERIVED_FROM edge). The
    parent is revoked with reason ``'rotated'`` (NON-cascading — a rotation must not reap
    the identity's sessions; only an explicit revoke cascades).

    Raises ValueError if the credential is missing or not currently active.
    """
    _assert_no_caller_id(caller_payload, "credential_id")
    parent = get_credential(credential_id)
    if parent is None:
        raise ValueError(f"Credential {credential_id!r} not found")
    if parent.get("status") != "active":
        raise ValueError(
            f"Credential {credential_id!r} is not rotatable: status={parent.get('status')!r}"
        )

    new_credential = issue_credential(
        agent_identity_id=parent["agent_identity_id"],
        rotated_from=credential_id,
    )
    revoked_parent = _revoke_one(credential_id, reason="rotated")
    logger.info("[INFO] Rotated credential %s -> %s", credential_id, new_credential["credential_id"])
    return {"new_credential": new_credential, "revoked_parent": revoked_parent}


def _revoke_one(credential_id: str, *, reason: str) -> Dict[str, Any]:
    """Conditionally flip a single credential active -> revoked. Idempotent-safe:
    an already-revoked credential returns its current item WITHOUT re-stamping
    revoked_at/revoked_reason (the conditional guards against double-revoke)."""
    ddb = _get_ddb()
    now = _now_z()
    try:
        resp = ddb.update_item(
            TableName=AGENT_CREDENTIALS_TABLE,
            Key={"credential_id": _serialize(credential_id)},
            UpdateExpression="SET #st = :revoked, revoked_at = :now, revoked_reason = :reason",
            ConditionExpression="#st = :active",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":revoked": _serialize("revoked"),
                ":active": _serialize("active"),
                ":now": _serialize(now),
                ":reason": _serialize(reason),
            },
            ReturnValues="ALL_NEW",
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            existing = get_credential(credential_id)
            if existing is None:
                raise ValueError(f"Credential {credential_id!r} not found") from exc
            # Already revoked — idempotent no-op (cascade re-entry / concurrent revoke).
            return existing
        raise
    return _deserialize(resp.get("Attributes", {}))


def revoke_credential(
    credential_id: str,
    reason: str = "revoked",
    *,
    caller_payload: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Revoke a credential and CASCADE (ENC-TSK-J04 AC#4).

    The cascade is a DynamoDB-side traversal (DynamoDB is the source of truth; the graph
    edges are a derived read-index that reflects the cascade asynchronously once the
    stream events flow through graph_sync). In one guarded sequence it:

      (a) flips this credential active -> revoked (conditional, no double-revoke);
      (b) retires every live session whose ``credential_id`` == this credential, via the
          existing append-only ``retire_session``; and
      (c) recursively revokes every credential whose ``rotated_from`` == this credential
          (the rotation-lineage descendants), reason ``'cascade:<root>'``.

    Idempotent and cycle-safe: a ``visited`` set guards against rotation cycles (which
    should be impossible given uuid4 parents, but a malformed ``rotated_from`` pointing at
    an ancestor is defended against), and each conditional flip is a no-op on an
    already-revoked credential. Returns a summary of everything reaped.
    """
    _assert_no_caller_id(caller_payload, "credential_id")
    if get_credential(credential_id) is None:
        raise ValueError(f"Credential {credential_id!r} not found")

    revoked: List[str] = []
    retired_sessions: List[str] = []
    skipped_sessions: List[Dict[str, str]] = []
    visited: set = set()

    def _cascade(cred_id: str, reason_for_this: str) -> None:
        if cred_id in visited:  # cycle / diamond guard
            return
        visited.add(cred_id)

        item = _revoke_one(cred_id, reason=reason_for_this)
        # Record only credentials that this call transitioned or that exist in-lineage.
        revoked.append(cred_id)

        # (b) reap sessions bound to this credential.
        for sess in list_sessions(credential_id=cred_id):
            sid = sess.get("session_id", "")
            if not sid or sess.get("status") == "retired":
                continue
            try:
                retire_session(sid)
                retired_sessions.append(sid)
            except ValueError as exc:
                skipped_sessions.append({"session_id": sid, "reason": str(exc)})

        # (c) recurse into rotation descendants (rotated_from == cred_id).
        for child in _credentials_rotated_from(cred_id):
            child_id = child.get("credential_id", "")
            if child_id and child_id not in visited:
                _cascade(child_id, reason_for_this=f"cascade:{credential_id}")

    _cascade(credential_id, reason_for_this=reason)

    summary = {
        "credential_id": credential_id,
        "reason": reason,
        "revoked_credentials": revoked,
        "revoked_count": len(revoked),
        "retired_sessions": retired_sessions,
        "retired_session_count": len(retired_sessions),
        "skipped_sessions": skipped_sessions,
    }
    logger.info("[INFO] Credential revoke cascade: %s", json.dumps(summary, default=str))
    return summary


def _credentials_rotated_from(parent_credential_id: str) -> List[Dict[str, Any]]:
    """Return all credential nodes whose ``rotated_from`` == ``parent_credential_id``."""
    ddb = _get_ddb()
    kwargs: Dict[str, Any] = {
        "TableName": AGENT_CREDENTIALS_TABLE,
        "FilterExpression": (
            "rotated_from = :parent AND NOT begins_with(credential_id, :ctr_pfx)"
        ),
        "ExpressionAttributeValues": {
            ":parent": _serialize(parent_credential_id),
            ":ctr_pfx": _serialize("counter#"),
        },
    }
    items: List[Dict[str, Any]] = []
    scan = ddb.scan(**kwargs)
    items.extend(_deserialize(r) for r in scan.get("Items", []))
    while scan.get("LastEvaluatedKey"):
        scan = ddb.scan(**kwargs, ExclusiveStartKey=scan["LastEvaluatedKey"])
        items.extend(_deserialize(r) for r in scan.get("Items", []))
    return items


def list_credentials(
    *,
    status: Optional[str] = None,
    agent_identity_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return all credential nodes, excluding counter# sentinel rows (none are minted for
    this table today, but the filter keeps the read uniform with the other stores)."""
    ddb = _get_ddb()
    filter_parts = ["NOT begins_with(credential_id, :ctr_pfx)"]
    expr_names: Dict[str, str] = {}
    expr_values: Dict[str, Any] = {":ctr_pfx": _serialize("counter#")}
    if status:
        filter_parts.append("#st = :status")
        expr_names["#st"] = "status"
        expr_values[":status"] = _serialize(status)
    if agent_identity_id:
        filter_parts.append("agent_identity_id = :aid")
        expr_values[":aid"] = _serialize(agent_identity_id)

    kwargs: Dict[str, Any] = {
        "TableName": AGENT_CREDENTIALS_TABLE,
        "FilterExpression": " AND ".join(filter_parts),
        "ExpressionAttributeValues": expr_values,
    }
    if expr_names:
        kwargs["ExpressionAttributeNames"] = expr_names

    items: List[Dict[str, Any]] = []
    scan = ddb.scan(**kwargs)
    items.extend(_deserialize(r) for r in scan.get("Items", []))
    while scan.get("LastEvaluatedKey"):
        scan = ddb.scan(**kwargs, ExclusiveStartKey=scan["LastEvaluatedKey"])
        items.extend(_deserialize(r) for r in scan.get("Items", []))
    return items
