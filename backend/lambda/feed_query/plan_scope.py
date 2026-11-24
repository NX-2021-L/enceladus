"""Plan selection and tree walk for GET /api/v1/feed/plan-scope (ENC-TSK-T05, ENC-PLN-108 W2.6).

Pure functions, no I/O: lambda_function.py does the reads, this module decides WHICH plans and WHICH tasks.

DOC-5E1E205FA664 section 5.3, rulings D-9 (the page is the newest 20 plans), D-26 (the three lifecycle timestamps
stay off the corpus row) and D-28 (parent rides the corpus row). The Plans page renders complete wave structure from
the corpus alone, then this read fills in the time scale. Rows are NOT built here: lambda_function.py passes the
records through corpus.build_tracker_entries_from_records at the plan scope, the same builder the corpus uses.

The selection mirrors the Plans lens so the page and the route agree on which plans are "the newest twenty":

  ordering   created_at descending (selectPlans, section 5.6 item 1, rule R5). A plan with no usable created_at sorts
             after every dated plan, and ties break on the plan id descending with digit runs compared as numbers,
             so the order is total and the same input always gives the same page. updated_at is deliberately not a
             fallback: R5 is creation order, and a recently touched old plan must not jump to the top.

  the tree   the plan's objectives_set (in stored order) are the roots, and every TASK reachable from a task root by
             parent pointers, at most MAX_DESCENDANT_DEPTH levels below it (resolveWaves.MAX_DESCENDANT_DEPTH: parent
             chains reach three levels below an objective in production). Only task rows are tree members, as in the
             lens. subtask_ids is never read: it disagrees with parent in production (fixture F5).
"""

from __future__ import annotations

import datetime as dt
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# Decision D-9: the newest 20 plans. Mirrors selectPlans.PLAN_PAGE_SIZE in the ui-v2 lens.
PLAN_PAGE_SIZE = 20

# Mirrors resolveWaves.MAX_DESCENDANT_DEPTH. Depth 1 is a direct child of an objective.
MAX_DESCENDANT_DEPTH = 3

# Hard ceiling on the task rows one call returns. Not a promise of a count: a bound on latency and bytes. The newest
# twenty plans are far below it in practice; if it is reached the response says so (`truncated`).
MAX_PLAN_TREE_TASKS = 3000

_DIGITS = re.compile(r"(\d+)")


def _parse_ts(raw: Any) -> Optional[float]:
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        parsed = dt.datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.timestamp()


def _natural_key(value: str) -> Tuple[Tuple[int, int, str], ...]:
    """Digit runs compare as numbers and sort before text, text compares case-insensitively.

    An approximation of the lens's localeCompare(..., 'en', {numeric: true}) tie-break. It only ever decides the order
    of plans that share a created_at (or have none), so a divergence from ICU collation on exotic ids is cosmetic."""
    parts: List[Tuple[int, int, str]] = []
    for chunk in _DIGITS.split(value):
        if chunk == "":
            continue
        if chunk.isdigit():
            parts.append((0, int(chunk), ""))
        else:
            parts.append((1, 0, chunk.casefold()))
    return tuple(parts)


def plan_sort_key(plan: Mapping[str, Any]) -> Tuple[int, float, Tuple[Tuple[int, int, str], ...]]:
    """Ascending key; callers sort with reverse=True so the newest dated plan is first and undated plans are last."""
    ts = _parse_ts(plan.get("created_at"))
    return (
        1 if ts is not None else 0,
        ts if ts is not None else 0.0,
        _natural_key(str(plan.get("plan_id") or "")),
    )


def newest_plans(plans: Iterable[Mapping[str, Any]], limit: int = PLAN_PAGE_SIZE) -> List[Mapping[str, Any]]:
    """The newest `limit` plans, newest first. `limit` is a bound, not a promise: fewer plans give fewer rows."""
    bound = max(0, int(limit))
    ordered = sorted(
        (p for p in plans if p.get("plan_id")),
        key=plan_sort_key,
        reverse=True,
    )
    return ordered[:bound]


def collect_tree_task_ids(
    plans: Sequence[Mapping[str, Any]],
    task_parents: Mapping[str, Tuple[str, str]],
    max_depth: int = MAX_DESCENDANT_DEPTH,
    max_tasks: int = MAX_PLAN_TREE_TASKS,
) -> Tuple[List[str], bool]:
    """Ids of the tasks in the trees of `plans`, and whether `max_tasks` cut the walk short.

    `task_parents` maps every TASK id the corpus knows to (project_id, parent id or ""). It is the only place a
    record's type comes from: an objective that is not in it (an issue, a feature, a missing or stale-closed record)
    is not a task row and is not walked. Descendants that are not tasks are never in it, so they are never walked.

    Each plan walks from its objectives in stored order, depth first, children in id order, at most `max_depth`
    levels below the objective. The walk keeps a per-root visited set, so a parent cycle terminates and a task that
    hangs under two plans or two roots is expanded under each. The returned ids are de-duplicated across plans, in discovery order.
    """
    children: Dict[str, List[str]] = {}
    for task_id, (_project, parent) in task_parents.items():
        if parent and parent != task_id:
            children.setdefault(parent, []).append(task_id)
    for kids in children.values():
        kids.sort()

    out: Dict[str, None] = {}
    truncated = False

    def add(task_id: str) -> bool:
        nonlocal truncated
        if task_id in out:
            return True
        if len(out) >= max_tasks:
            truncated = True
            return False
        out[task_id] = None
        return True

    def walk(task_id: str, depth: int, seen: set) -> bool:
        if depth > max_depth:
            return True
        for kid in children.get(task_id, ()):
            if kid in seen:
                continue
            seen.add(kid)
            if not add(kid):
                return False
            if not walk(kid, depth + 1, seen):
                return False
        return True

    for plan in plans:
        roots: List[str] = []
        for objective in plan.get("objectives_set") or []:
            if isinstance(objective, str) and objective in task_parents and objective not in roots:
                roots.append(objective)
        for root in roots:
            # Visited per ROOT, not per plan: a root that is itself a descendant of an earlier root must still be
            # expanded to its own depth, and a per-plan set would skip children the earlier root reached at its limit.
            if not add(root) or not walk(root, 1, {root}):
                return list(out), truncated
    return list(out), truncated
