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

from typing import Any, Dict, Mapping, Optional

from botocore.exceptions import BotoCoreError, ClientError

from config import AGENT_SESSIONS_TABLE, AGENT_TYPES_TABLE, logger
from aws_clients import _get_ddb
from serialization import _deserialize, _now_z, _serialize

__all__ = [
    "SESSION_ID_PREFIX",
    "AGENT_TYPE_ID_PREFIX",
    "SESSION_STATUSES",
    "AGENT_TYPE_STATUSES",
    "encode_seq",
    "mint_session_id",
    "mint_agent_type_id",
    "get_session",
    "get_agent_type",
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
