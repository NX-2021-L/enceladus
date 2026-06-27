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

from typing import Any, Dict, List, Mapping, Optional

from botocore.exceptions import BotoCoreError, ClientError

from config import AGENT_SESSIONS_TABLE, AGENT_TYPES_TABLE, logger
from aws_clients import _get_ddb
from serialization import _deserialize, _now_z, _serialize

__all__ = [
    "SESSION_ID_PREFIX",
    "AGENT_TYPE_ID_PREFIX",
    "SESSION_STATUSES",
    "AGENT_TYPE_STATUSES",
    "SESSION_NODE_PROPERTIES",
    "AGENT_TYPE_NODE_PROPERTIES",
    "encode_seq",
    "mint_session_id",
    "mint_agent_type_id",
    "get_session",
    "get_agent_type",
    "claim_session",
    "retire_session",
    "list_sessions",
    "list_agent_types",
    "find_agent_type",
    "IdAllocationError",
    "CallerSuppliedIdError",
]

# ---------------------------------------------------------------------------
# Format constants — the shared v3/v4 id-space (the migration seam)
# ---------------------------------------------------------------------------
SESSION_ID_PREFIX = "ENC-SES"
AGENT_TYPE_ID_PREFIX = "ENC-AGT"

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
    caller_payload: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Mint a server-allocated ENC-SES-NNN and persist the session node. Returns the
    persisted item (including the minted ``session_id``). The caller never supplies the id.

    ``status`` defaults to ``allocated`` (the pre-allocate/claim flow for a dispatched
    session); pass ``claimed`` for a self-allocating root/ad-hoc session, in which case
    ``claimed_at`` defaults to mint time.
    """
    _assert_no_caller_id(caller_payload, "session_id")
    if status not in SESSION_STATUSES:
        raise ValueError(f"status must be one of {SESSION_STATUSES}, got {status!r}")
    if not agent_type_id:
        raise ValueError("agent_type_id is required to mint a session")

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
# Directory reads — paginated scans (ENC-TSK-I38)
# ---------------------------------------------------------------------------

def list_sessions(
    *,
    status: Optional[str] = None,
    agent_type_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return all session nodes, excluding counter# sentinel rows.

    Accepts optional ``status`` and ``agent_type_id`` filters. Results are
    returned in DynamoDB scan order (unordered within a page).
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
