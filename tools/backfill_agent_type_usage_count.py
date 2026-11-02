#!/usr/bin/env python3
"""ENC-TSK-R81-0H / ENC-FTR-146 AC-6: one-shot backfill of agent-types.usage_count.

Counts sessions per agent_type_id in the agent-sessions table and reconciles
``usage_count`` on each agent-types row.

DRY-RUN by default (read-only; prints per-type counts). ``--apply`` writes and is io-gated:
it also requires ``--approved-by <name>`` and must be run from a governed (privileged)
terminal, because the agent IAM user cannot write DynamoDB.

Apply uses ``ADD usage_count :delta`` where delta = sessions_counted - usage_count_read_at_scan.
Concurrent agent.register calls (which bump session + counter atomically) therefore never
get clobbered, and a re-run recomputes delta from live values (idempotent in effect).
Only canonical ENC-AGT-NNN session rows are counted; free-text / unknown ids are reported as
orphans and left for ENC-FTR-146 AC-7 (W2.2) rewrite. ``counter#`` sentinel rows are skipped.

Usage:
  AWS_PROFILE=enceladus-agent python3 tools/backfill_agent_type_usage_count.py
  AWS_PROFILE=product-lead python3 tools/backfill_agent_type_usage_count.py --apply --approved-by io
Env: AGENT_SESSIONS_TABLE (agent-sessions), AGENT_TYPES_TABLE (agent-types), AWS_REGION.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Tuple

AGENT_TYPE_ID_PATTERN = re.compile(r"^ENC-AGT-[0-9A-Z]{3,}$")
SESSIONS_TABLE = os.environ.get("AGENT_SESSIONS_TABLE", "agent-sessions")
TYPES_TABLE = os.environ.get("AGENT_TYPES_TABLE", "agent-types")


def count_sessions(session_rows: Iterable[Dict[str, Any]]) -> Tuple[Counter, Counter, int]:
    """Return (per_type_counts, orphan_counts, total_sessions) over plain-dict rows."""
    per_type: Counter = Counter()
    orphans: Counter = Counter()
    total = 0
    for row in session_rows:
        sid = str(row.get("session_id") or "")
        if not sid or sid.startswith("counter#"):
            continue
        total += 1
        aid = str(row.get("agent_type_id") or "").strip()
        if AGENT_TYPE_ID_PATTERN.match(aid):
            per_type[aid] += 1
        else:
            orphans[aid or "<missing>"] += 1
    return per_type, orphans, total


def plan_updates(per_type: Counter, type_rows: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One plan entry per agent-types row (and per counted id with no row)."""
    plan: List[Dict[str, Any]] = []
    for aid in sorted(set(type_rows) | set(per_type)):
        row = type_rows.get(aid)
        current = int((row or {}).get("usage_count") or 0)
        target = int(per_type.get(aid, 0))
        plan.append({
            "agent_type_id": aid, "exists": row is not None,
            "status": (row or {}).get("status"), "current": current,
            "target": target, "delta": target - current,
        })
    return plan


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


def apply_plan(ddb, plan: List[Dict[str, Any]]) -> int:
    from botocore.exceptions import ClientError
    applied = 0
    for p in plan:
        if not p["exists"] or p["delta"] == 0:
            continue
        try:
            ddb.update_item(
                TableName=TYPES_TABLE,
                Key={"agent_type_id": {"S": p["agent_type_id"]}},
                UpdateExpression="ADD #uc :d",
                ConditionExpression="attribute_exists(agent_type_id)",
                ExpressionAttributeNames={"#uc": "usage_count"},
                ExpressionAttributeValues={":d": {"N": str(p["delta"])}},
            )
            applied += 1
        except ClientError as exc:
            print(f"[ERROR] {p['agent_type_id']}: {exc}", file=sys.stderr)
    return applied


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--apply", action="store_true", help="write usage_count (io-gated; default is dry-run)")
    ap.add_argument("--approved-by", default="", help="required with --apply: who authorized the write")
    args = ap.parse_args(argv)
    if args.apply and not args.approved_by.strip():
        print("[ERROR] --apply requires --approved-by <name> (io-gated governed path)", file=sys.stderr)
        return 2

    import boto3
    ddb = boto3.client("dynamodb", region_name=os.environ.get("AWS_REGION", "us-west-2"))
    sessions = _scan(ddb, SESSIONS_TABLE, "session_id, agent_type_id")
    types = {r["agent_type_id"]: r for r in _scan(
        ddb, TYPES_TABLE, "agent_type_id, #s, usage_count", {"#s": "status"}) if "agent_type_id" in r
        and not str(r["agent_type_id"]).startswith("counter#")}
    per_type, orphans, total = count_sessions(sessions)
    plan = plan_updates(per_type, types)

    print(f"mode={'APPLY' if args.apply else 'DRY-RUN'} sessions_table={SESSIONS_TABLE} types_table={TYPES_TABLE}")
    print(f"{'agent_type_id':<14}{'status':<12}{'current':>8}{'sessions':>9}{'delta':>7}")
    for p in plan:
        flag = "" if p["exists"] else "  (no agent-types row)"
        print(f"{p['agent_type_id']:<14}{str(p['status']):<12}{p['current']:>8}{p['target']:>9}{p['delta']:>+7}{flag}")
    counted = sum(per_type.values())
    print(f"sessions_total={total} counted_canonical={counted} orphans={sum(orphans.values())} "
          f"sum_usage_count_after={sum(p['target'] for p in plan if p['exists'])}")
    for k, v in orphans.most_common():
        print(f"  orphan agent_type_id={k!r}: {v}")
    if args.apply:
        print(f"applied={apply_plan(ddb, plan)} approved_by={args.approved_by.strip()}")
    else:
        print("dry-run only; re-run with --apply --approved-by <name> from a governed terminal to write")
    return 0


if __name__ == "__main__":
    sys.exit(main())
