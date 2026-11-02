#!/usr/bin/env python3
"""ENC-TSK-R82-0B / ENC-FTR-146 AC-7: rewrite orphan agent-sessions to a canonical ENC-AGT type.

An "orphan" is an agent-sessions row whose ``agent_type_id`` is not an ``ENC-AGT-*`` id
(free text such as ``claude_code_cli``, ``coord-lead``). Each orphan is mapped to:

  1. an existing ACTIVE agent-types row, via the W0.6 canonical normal form
     (``canonicalize_surface`` on the orphan value; DOC-82CF8C268DA5). When more than one
     ACTIVE row shares that surface, the session's ``runtime`` is used as a *model hint*
     (``canonicalize_model``) and the mapping is taken only if exactly one row matches. The
     script never guesses between candidates;
  2. otherwise the designated fallback ("unknown"/"unregistered") agent type.

The rewrite sets ``agent_type_id`` = canonical id and preserves the original value in
``legacy_agent_type_id``. No rows are deleted. A rewritten row no longer matches the orphan
filter, so a re-run is a no-op (idempotent); the write is also conditional on the row still
holding the scanned orphan value and no ``legacy_agent_type_id``.

If no fallback row exists the script REFUSES ``--apply`` (it never creates the type) and
names the ``agent.type.register`` call that does. Use ``--fallback-type-id ENC-AGT-xxx`` to
pin a specific row instead of auto-detecting by surface/model label.

DRY-RUN by default (read-only; prints per-target counts, never session contents).
``--apply`` is io-gated: it needs ``--approved-by <name>`` and a privileged terminal (the
agent IAM user cannot write DynamoDB). ORDER: apply this first, THEN re-run
tools/backfill_agent_type_usage_count.py so usage_count includes the rewritten sessions.

Usage:
  AWS_PROFILE=enceladus-agent python3 tools/backfill_orphan_sessions.py
  AWS_PROFILE=product-lead python3 tools/backfill_orphan_sessions.py --apply --approved-by io
Env: AGENT_SESSIONS_TABLE (agent-sessions), AGENT_TYPES_TABLE (agent-types), AWS_REGION.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "backend", "lambda", "coordination_api"))
from agent_id_alloc import canonicalize_model, canonicalize_surface  # noqa: E402

AGENT_TYPE_ID_PATTERN = re.compile(r"^ENC-AGT-[0-9A-Z]{3,}$")
SESSIONS_TABLE = os.environ.get("AGENT_SESSIONS_TABLE", "agent-sessions")
TYPES_TABLE = os.environ.get("AGENT_TYPES_TABLE", "agent-types")
FALLBACK_LABELS = ("unknown", "unregistered")

REASON_SURFACE = "surface"
REASON_SURFACE_MODEL = "surface+model-hint"
REASON_FALLBACK_NO_MATCH = "fallback:no-active-surface-match"
REASON_FALLBACK_AMBIGUOUS = "fallback:ambiguous-surface"


def is_orphan(row: Dict[str, Any]) -> bool:
    sid = str(row.get("session_id") or "")
    if not sid or sid.startswith("counter#"):
        return False
    return not AGENT_TYPE_ID_PATTERN.match(str(row.get("agent_type_id") or "").strip())


def find_fallback_type(type_rows: Dict[str, Dict[str, Any]], explicit: str = "") -> Optional[str]:
    """ACTIVE row pinned by --fallback-type-id, else the one whose surface/model is a fallback label."""
    if explicit:
        row = type_rows.get(explicit)
        return explicit if row and str(row.get("status")) == "active" else None
    for aid in sorted(type_rows):
        row = type_rows[aid]
        if str(row.get("status")) != "active":
            continue
        if canonicalize_surface(row.get("surface")) in FALLBACK_LABELS \
                or canonicalize_model(row.get("model")) in FALLBACK_LABELS:
            return aid
    return None


def map_orphan(row: Dict[str, Any], type_rows: Dict[str, Dict[str, Any]],
               fallback_id: Optional[str]) -> Tuple[Optional[str], str]:
    """Return (target ENC-AGT id or None when no fallback exists, reason)."""
    surface = canonicalize_surface(row.get("agent_type_id"))
    active = [a for a in sorted(type_rows) if str(type_rows[a].get("status")) == "active"]
    cands = [a for a in active if surface and canonicalize_surface(type_rows[a].get("surface")) == surface]
    if len(cands) == 1:
        return cands[0], REASON_SURFACE
    if len(cands) > 1:
        model = canonicalize_model(row.get("runtime"))
        narrowed = [a for a in cands if model and canonicalize_model(type_rows[a].get("model")) == model]
        if len(narrowed) == 1:
            return narrowed[0], REASON_SURFACE_MODEL
        return fallback_id, REASON_FALLBACK_AMBIGUOUS
    return fallback_id, REASON_FALLBACK_NO_MATCH


def plan_rewrites(session_rows: Iterable[Dict[str, Any]], type_rows: Dict[str, Dict[str, Any]],
                  fallback_id: Optional[str]) -> List[Dict[str, Any]]:
    plan: List[Dict[str, Any]] = []
    for row in session_rows:
        if not is_orphan(row):
            continue
        target, reason = map_orphan(row, type_rows, fallback_id)
        plan.append({"session_id": row["session_id"],
                     "original": str(row.get("agent_type_id") or ""),
                     "target": target, "reason": reason})
    return plan


def fallback_missing_message() -> str:
    return ("[ERROR] no ACTIVE fallback agent type exists (surface/model 'unknown' or 'unregistered'). "
            "Refusing --apply; this script never creates it. Create it first with: "
            "coordination(action='agent.type.register', arguments={surface:'unknown', model:'unknown'}) "
            "(or surface 'unregistered' per FTR-146 AC-7 wording), then re-run; or pin an existing row "
            "with --fallback-type-id ENC-AGT-xxx. NOTE: surface is a closed enum (ALLOWED_SURFACES in "
            "agent_id_alloc.py), so the label must be added there before register will accept it.")


def _scan(ddb, table: str, projection: str, names: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    from boto3.dynamodb.types import TypeDeserializer
    de = TypeDeserializer()
    out: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {"TableName": table, "ProjectionExpression": projection, "ConsistentRead": True}
    if names:
        kwargs["ExpressionAttributeNames"] = names
    while True:
        resp = ddb.scan(**kwargs)
        out.extend({k: de.deserialize(v) for k, v in it.items()} for it in resp.get("Items", []))
        if not resp.get("LastEvaluatedKey"):
            return out
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def apply_plan(ddb, plan: List[Dict[str, Any]], sessions_table: str = SESSIONS_TABLE) -> Tuple[int, int]:
    """Rewrite rows. Returns (applied, skipped). Row is never deleted; original is preserved."""
    from botocore.exceptions import ClientError
    applied = skipped = 0
    for p in plan:
        if not p["target"]:
            skipped += 1
            continue
        try:
            ddb.update_item(
                TableName=sessions_table,
                Key={"session_id": {"S": p["session_id"]}},
                UpdateExpression="SET agent_type_id = :c, legacy_agent_type_id = :o",
                ConditionExpression=("attribute_exists(session_id) AND agent_type_id = :o "
                                     "AND attribute_not_exists(legacy_agent_type_id)"),
                ExpressionAttributeValues={":c": {"S": p["target"]}, ":o": {"S": p["original"]}},
            )
            applied += 1
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                skipped += 1  # already rewritten / changed concurrently: idempotent skip
                continue
            print(f"[ERROR] session rewrite failed: {exc.response.get('Error', {}).get('Code')}", file=sys.stderr)
    return applied, skipped


def summarize(plan: List[Dict[str, Any]]) -> Dict[str, Counter]:
    return {
        "by_target": Counter(p["target"] or "<NO FALLBACK>" for p in plan),
        "by_reason": Counter(p["reason"] for p in plan),
        "by_mapping": Counter((p["original"] or "<missing>", p["target"] or "<NO FALLBACK>") for p in plan),
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--apply", action="store_true", help="write the rewrite (io-gated; default is dry-run)")
    ap.add_argument("--approved-by", default="", help="required with --apply: who authorized the write")
    ap.add_argument("--fallback-type-id", default="", help="pin the ACTIVE ENC-AGT row used as the fallback")
    args = ap.parse_args(argv)
    if args.apply and not args.approved_by.strip():
        print("[ERROR] --apply requires --approved-by <name> (io-gated governed path)", file=sys.stderr)
        return 2

    import boto3
    ddb = boto3.client("dynamodb", region_name=os.environ.get("AWS_REGION", "us-west-2"))
    sessions = _scan(ddb, SESSIONS_TABLE, "session_id, agent_type_id, #r", {"#r": "runtime"})
    types = {r["agent_type_id"]: r for r in _scan(
        ddb, TYPES_TABLE, "agent_type_id, #s, surface, #m", {"#s": "status", "#m": "model"})
        if "agent_type_id" in r and not str(r["agent_type_id"]).startswith("counter#")}
    fallback_id = find_fallback_type(types, args.fallback_type_id.strip())
    plan = plan_rewrites(sessions, types, fallback_id)
    s = summarize(plan)

    print(f"mode={'APPLY' if args.apply else 'DRY-RUN'} sessions_table={SESSIONS_TABLE} types_table={TYPES_TABLE}")
    print(f"sessions_scanned={len(sessions)} orphans={len(plan)} fallback_type={fallback_id or 'NONE'}")
    print("per-target:")
    for k, v in s["by_target"].most_common():
        print(f"  {k}: {v}")
    print("per-reason:")
    for k, v in s["by_reason"].most_common():
        print(f"  {k}: {v}")
    print("per-mapping (original agent_type_id -> target):")
    for (o, t), v in s["by_mapping"].most_common():
        print(f"  {o!r} -> {t}: {v}")
    unmapped = sum(1 for p in plan if not p["target"])
    if unmapped:
        print(f"[WARN] {unmapped} orphan(s) have no target (fallback type missing)")
    if args.apply:
        if unmapped:
            print(fallback_missing_message(), file=sys.stderr)
            return 3
        applied, skipped = apply_plan(ddb, plan)
        print(f"applied={applied} skipped={skipped} approved_by={args.approved_by.strip()}")
        print("NEXT: re-run tools/backfill_agent_type_usage_count.py (--apply --approved-by ...) now.")
    else:
        if unmapped:
            print(fallback_missing_message())
        print("dry-run only; re-run with --apply --approved-by <name> from a governed terminal to write")
    return 0


if __name__ == "__main__":
    sys.exit(main())
