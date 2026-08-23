"""Project the governed record store to mart grain.

BRD B3-R3, second clause: *project to grain*. Seven builders, one per declared
table in ``mart_schema``. Each returns ``list[dict]`` keyed by the DECLARED
column names; the shared B2-R2 library does the rest (declaration wins, absent
columns become NULL, extra keys are dropped).

Two disciplines run through every builder:

**The substitution test.** Free text is read and discarded, never emitted. The
sharpest case is ``fact_record_transition``: the tracker does not store status
transitions structurally at all -- ``history[].status`` is an entry KIND
(``created`` / ``worklog``), and the actual transition lives inside the entry's
prose. So this module parses the prose to recover two status TOKENS and a
timestamp, and throws the prose away. What lands in the mart is
``('in-progress' -> 'coding-complete', 62.4 minutes)``; what does not land is
the sentence that carried it.

**Daily grain from the outset.** Every fact builder emits one row per day per
grain tuple across the whole observed history, recomputed from scratch on
every refresh. Nothing is incremental, so nothing can silently stop advancing
while continuing to look fresh.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

__all__ = [
    "TERMINAL_STATUSES",
    "INITIAL_STATUS",
    "ontology_completeness_score",
    "extract_transitions",
    "build_dim_record",
    "build_fact_record_daily",
    "build_fact_record_transition",
    "build_dim_document",
    "build_fact_document_daily",
    "build_fact_session_daily",
    "build_fact_graph_health_daily",
    "build_all",
]

# ---------------------------------------------------------------------------
# Status vocabulary
# ---------------------------------------------------------------------------

#: Statuses that end a record's life. The tracker's governed task lifecycle
#: terminates at `closed`; other record types (plans, lessons, escalations,
#: references) carry their own terminal vocabulary, and legacy records carry
#: capitalised variants. Compared case-folded.
TERMINAL_STATUSES = frozenset(
    {
        "closed", "completed", "complete", "wont_fix", "superseded",
        "archived", "denied", "denied_with_guidance", "incomplete",
    }
)

#: The tracker creates task / issue / feature records at `open`. A record's
#: status before its FIRST recorded transition is not stored anywhere, so this
#: is the documented assumption standing in for it. It affects only the days
#: between creation and first transition, and only for records whose real
#: initial status differed -- overwhelmingly plans and references, which mostly
#: carry no transitions at all.
INITIAL_STATUS = "open"


def is_terminal(status: Optional[str]) -> bool:
    return bool(status) and str(status).strip().lower() in TERMINAL_STATUSES


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

_ISO = "%Y-%m-%dT%H:%M:%SZ"


def parse_ts(value: Any) -> Optional[datetime]:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return datetime.strptime(text[:20], _ISO).replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def to_date(value: Any) -> Optional[date]:
    moment = parse_ts(value)
    return moment.date() if moment else None


def date_range(first: date, last: date) -> Iterable[date]:
    step = first
    one = timedelta(days=1)
    while step <= last:
        yield step
        step += one


# ---------------------------------------------------------------------------
# Ontology completeness (ENC-FTR-011)
# ---------------------------------------------------------------------------

_COMMON_CHECKS = (("title", 10), ("description", 5), ("priority", 5), ("category", 10), ("intent", 5))
_TASK_CHECKS = (("acceptance_criteria", 15), ("assigned_to", 5), ("parent", 10), ("checklist", 5))
_ISSUE_CHECKS = (("evidence", 25), ("severity", 5), ("hypothesis", 10), ("technical_notes", 5))
_FEATURE_CHECKS = (("user_story", 15), ("acceptance_criteria", 15), ("owners", 5), ("success_metrics", 5), ("parent", 5))


def _has_value(value: Any) -> bool:
    if isinstance(value, list):
        return len(value) > 0
    if isinstance(value, str):
        return bool(value.strip())
    return bool(value)


def ontology_completeness_score(record: Mapping[str, Any]) -> int:
    """Recompute the 0-100 ontology completeness score.

    Deliberately a re-implementation of the record store's own rubric
    (``tools/enceladus-mcp-server/server.py::_compute_completeness_score``)
    rather than a read of a stored field: the score is computed at READ time by
    the MCP server and never persisted to DynamoDB, so a mart that scanned the
    table would find no column to project. Verified against the live API for
    DVP-TSK-648 (55/70 -> 79).
    """
    record_type = record.get("record_type", "")
    earned = 0
    total = 0

    for field, points in _COMMON_CHECKS:
        total += points
        if _has_value(record.get(field)):
            earned += points

    if record_type == "feature":
        for field, points in _FEATURE_CHECKS:
            total += points
            if _has_value(record.get(field)):
                earned += points
        total += 15
        criteria = record.get("acceptance_criteria") or []
        if criteria:
            validated = sum(
                1 for item in criteria if isinstance(item, dict) and item.get("evidence_acceptance")
            )
            if validated == len(criteria):
                earned += 15
            elif validated > 0:
                earned += round(15 * validated / len(criteria))
    elif record_type == "task":
        for field, points in _TASK_CHECKS:
            total += points
            if _has_value(record.get(field)):
                earned += points
    elif record_type == "issue":
        for field, points in _ISSUE_CHECKS:
            total += points
            if _has_value(record.get(field)):
                earned += points

    return round((earned / total) * 100) if total else 0


# ---------------------------------------------------------------------------
# Transition extraction from the per-record history arrays
# ---------------------------------------------------------------------------

#: The tracker records a status change as prose inside a worklog entry. Both
#: shapes below appear in the live corpus (15,422 and 108 occurrences
#: respectively across 58,042 history entries), plus an underscored legacy
#: variant written by an older `tracker.py`. Underscores are accepted in the
#: capture and folded to the governed hyphenated form.
_STATUS_PATTERNS = (
    re.compile(r"Field 'status' set to '([A-Za-z0-9_\- ]+)'"),
    re.compile(r"Status changed to '([A-Za-z0-9_\- ]+)'"),
)

#: Any governed agent session named in a worklog entry. 11,989 history entries
#: carry one, which is what makes `fact_session_daily.records_touched`
#: answerable at all -- there is no stored session->record edge.
_SESSION_PATTERN = re.compile(r"ENC-SES-[A-Z0-9]{3}")


def _normalise_status(raw: str) -> str:
    return raw.strip().replace("_", "-").lower()


def extract_transitions(record: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Recover the lifecycle transition chain from one record's history array.

    Returns transitions in chronological order. ``from_status`` is carried
    forward from the previous transition (``INITIAL_STATUS`` for the first),
    and ``days_in_prior_status`` measures against the previous transition's
    timestamp, or the record's creation time for the first.

    The history entry's ``description`` is read here and never returned.
    """
    history = record.get("history") or []
    created = parse_ts(record.get("created_at"))

    events: List[Tuple[datetime, str]] = []
    for entry in history:
        if not isinstance(entry, dict):
            continue
        description = entry.get("description") or ""
        moment = parse_ts(entry.get("timestamp"))
        if not moment:
            continue
        for pattern in _STATUS_PATTERNS:
            found = pattern.search(description)
            if found:
                events.append((moment, _normalise_status(found.group(1))))
                break

    events.sort(key=lambda pair: pair[0])

    transitions: List[Dict[str, Any]] = []
    previous_status = INITIAL_STATUS
    previous_moment = created
    for moment, status in events:
        if status == previous_status:
            # A re-assertion of the same status is not a transition. Recording
            # it would inflate throughput and zero out cycle time.
            continue
        elapsed = None
        if previous_moment and moment >= previous_moment:
            elapsed = round((moment - previous_moment).total_seconds() / 86400.0, 6)
        transitions.append(
            {
                "from_status": previous_status,
                "to_status": status,
                "transitioned_at": moment.strftime(_ISO),
                "days_in_prior_status": elapsed,
            }
        )
        previous_status = status
        previous_moment = moment
    return transitions


def sessions_in_history(record: Mapping[str, Any]) -> Set[str]:
    """Every governed agent session that wrote to this record."""
    found: Set[str] = set()
    active = record.get("active_agent_session_id")
    if isinstance(active, str) and active.startswith("ENC-SES-"):
        found.add(active)
    for entry in record.get("history") or []:
        if isinstance(entry, dict):
            found.update(_SESSION_PATTERN.findall(entry.get("description") or ""))
    return found


# ---------------------------------------------------------------------------
# Status timeline
# ---------------------------------------------------------------------------


def status_timeline(record: Mapping[str, Any], transitions: Sequence[Mapping[str, Any]]) -> List[Tuple[date, str]]:
    """Segments of (start_date, status) for one record, chronological.

    The final segment is forced to the record's CURRENT status: the parsed
    chain and the authoritative `status` field can disagree when a status was
    set by a path that did not write a parseable worklog line, and the record
    store wins.
    """
    created = to_date(record.get("created_at"))
    if not created:
        return []
    segments: List[Tuple[date, str]] = [(created, INITIAL_STATUS)]
    for transition in transitions:
        moment = to_date(transition["transitioned_at"])
        if moment:
            segments.append((moment, str(transition["to_status"])))
    current = record.get("status")
    if current:
        segments[-1] = (segments[-1][0], str(current))
    return segments


def _status_on_days(segments: Sequence[Tuple[date, str]], last_day: date) -> Dict[date, str]:
    """Status held at the END of each day, from creation through last_day.

    Several transitions can land on one day; the day holds the LAST of them,
    which is what "at end of day" means and what keeps `record_count` a true
    partition of the record set (one row per record per day, never two).
    """
    if not segments:
        return {}
    latest_on_start: Dict[date, str] = {}
    for start, status in segments:
        latest_on_start[start] = status  # later entries overwrite same-day ones

    starts = sorted(latest_on_start)
    held: Dict[date, str] = {}
    for index, start in enumerate(starts):
        if start > last_day:
            break
        end = starts[index + 1] - timedelta(days=1) if index + 1 < len(starts) else last_day
        for day in date_range(start, min(end, last_day)):
            held[day] = latest_on_start[start]
    return held


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def build_dim_record(corpus) -> List[Dict[str, Any]]:
    """DVP-TSK-672. One row per governed tracker record, current state."""
    rows: List[Dict[str, Any]] = []
    for record in corpus.records:
        item_id = record.get("item_id") or str(record.get("record_id", "")).split("#")[-1]
        if not item_id:
            continue
        transitions = extract_transitions(record)
        closed_at = ""
        for transition in reversed(transitions):
            if is_terminal(transition["to_status"]):
                closed_at = transition["transitioned_at"]
                break
        if not closed_at and is_terminal(record.get("status")):
            closed_at = str(record.get("updated_at") or "")

        components = record.get("components") or []
        if not isinstance(components, list):
            components = [components]

        rows.append(
            {
                "record_id": item_id,
                "project_id": record.get("project_id") or "",
                "record_type": record.get("record_type") or "",
                "status": record.get("status") or "",
                "priority": record.get("priority") or "",
                "category": record.get("category") or "",
                "parent_id": record.get("parent") or "",
                "component_ids": json.dumps([str(item) for item in components], separators=(",", ":")),
                "created_at": record.get("created_at") or "",
                "updated_at": record.get("updated_at") or "",
                "closed_at": closed_at,
                "checkout_count": int(record.get("checkout_count") or 0),
                "closed_count": int(record.get("closed_count") or 0),
                "ontology_completeness_score": ontology_completeness_score(record),
                "transition_type": record.get("transition_type") or "",
            }
        )
    return rows


def build_fact_record_daily(corpus, last_day: date) -> List[Dict[str, Any]]:
    """DVP-TSK-673. Grain (snapshot_date, project_id, record_type, status)."""
    counts: Dict[Tuple[date, str, str, str], Dict[str, int]] = defaultdict(
        lambda: {"record_count": 0, "opened_count": 0, "closed_count": 0}
    )

    for record in corpus.records:
        created = to_date(record.get("created_at"))
        if not created or created > last_day:
            continue
        project = record.get("project_id") or ""
        record_type = record.get("record_type") or ""
        transitions = extract_transitions(record)
        held = _status_on_days(status_timeline(record, transitions), last_day)

        for day, status in held.items():
            bucket = counts[(day, project, record_type, status)]
            bucket["record_count"] += 1
            if day == created:
                bucket["opened_count"] += 1

        for transition in transitions:
            if not is_terminal(transition["to_status"]):
                continue
            day = to_date(transition["transitioned_at"])
            if day and day <= last_day:
                status = held.get(day, str(transition["to_status"]))
                counts[(day, project, record_type, status)]["closed_count"] += 1

    return [
        {
            "snapshot_date": day,
            "project_id": project,
            "record_type": record_type,
            "status": status,
            "record_count": values["record_count"],
            "opened_count": values["opened_count"],
            "closed_count": values["closed_count"],
        }
        for (day, project, record_type, status), values in sorted(
            counts.items(), key=lambda pair: (pair[0][0], pair[0][1], pair[0][2], pair[0][3])
        )
    ]


def build_fact_record_transition(corpus) -> List[Dict[str, Any]]:
    """DVP-TSK-674. One row per lifecycle transition."""
    rows: List[Dict[str, Any]] = []
    for record in corpus.records:
        item_id = record.get("item_id") or str(record.get("record_id", "")).split("#")[-1]
        if not item_id:
            continue
        for transition in extract_transitions(record):
            rows.append(
                {
                    "record_id": item_id,
                    "project_id": record.get("project_id") or "",
                    "record_type": record.get("record_type") or "",
                    "from_status": transition["from_status"],
                    "to_status": transition["to_status"],
                    "transitioned_at": transition["transitioned_at"],
                    "days_in_prior_status": transition["days_in_prior_status"],
                    "transition_type": record.get("transition_type") or "",
                    "snapshot_date": to_date(transition["transitioned_at"]),
                }
            )
    rows.sort(key=lambda row: (row["transitioned_at"], row["record_id"]))
    return rows


def build_dim_document(corpus) -> List[Dict[str, Any]]:
    """DVP-TSK-675. One row per docstore document. No content."""
    rows: List[Dict[str, Any]] = []
    for document in corpus.documents:
        document_id = document.get("document_id")
        if not document_id:
            continue
        warnings = document.get("compliance_warnings") or []
        related = document.get("related_items") or []
        score = document.get("compliance_score")
        rows.append(
            {
                "document_id": document_id,
                "project_id": document.get("project_id") or "",
                "document_subtype": document.get("document_subtype") or "unspecified",
                "subtypepattern": document.get("subtypepattern") or "",
                "status": document.get("status") or "",
                "document_maturity_state": document.get("document_maturity_state") or "unspecified",
                "compliance_score": int(score) if score is not None else None,
                "compliance_warning_count": len(warnings) if isinstance(warnings, list) else 0,
                "size_bytes": int(document.get("size_bytes") or 0),
                "version": int(document.get("version") or 0),
                "related_item_count": len(related) if isinstance(related, list) else 0,
                "created_at": document.get("created_at") or "",
                "updated_at": document.get("updated_at") or "",
            }
        )
    return rows


def build_fact_document_daily(corpus, last_day: date) -> List[Dict[str, Any]]:
    """DVP-TSK-676. Grain (snapshot_date, project_id, subtype, maturity).

    Subtype and maturity are CURRENT attributes projected across the document's
    lifetime: the docstore keeps no maturity history, so a document that
    matured yesterday reads as mature for its whole life here. That is a
    type-1-dimension limitation of the source, recorded rather than hidden --
    it makes maturity MOVEMENT over time readable only from the current
    distribution, while document PRODUCTION per day stays exact.
    """
    counts: Dict[Tuple[date, str, str, str], Dict[str, Any]] = defaultdict(
        lambda: {"document_count": 0, "created_count": 0, "score_sum": 0, "score_n": 0}
    )
    for document in corpus.documents:
        created = to_date(document.get("created_at"))
        if not created or created > last_day:
            continue
        project = document.get("project_id") or ""
        subtype = document.get("document_subtype") or "unspecified"
        maturity = document.get("document_maturity_state") or "unspecified"
        score = document.get("compliance_score")
        for day in date_range(created, last_day):
            bucket = counts[(day, project, subtype, maturity)]
            bucket["document_count"] += 1
            if day == created:
                bucket["created_count"] += 1
            if score is not None:
                bucket["score_sum"] += int(score)
                bucket["score_n"] += 1

    rows: List[Dict[str, Any]] = []
    for (day, project, subtype, maturity), values in sorted(
        counts.items(), key=lambda pair: (pair[0][0], pair[0][1], pair[0][2], pair[0][3])
    ):
        rows.append(
            {
                "snapshot_date": day,
                "project_id": project,
                "document_subtype": subtype,
                "document_maturity_state": maturity,
                "document_count": values["document_count"],
                "created_count": values["created_count"],
                "mean_compliance_score": (
                    round(values["score_sum"] / values["score_n"], 4) if values["score_n"] else None
                ),
            }
        )
    return rows


def build_fact_session_daily(corpus) -> List[Dict[str, Any]]:
    """DVP-TSK-677. Grain (snapshot_date, project_id, agent_type, model).

    There is no stored session -> record edge, so the linkage is inverted out
    of the tracker: every governed session named in a record's history (or
    holding its checkout) is counted as having touched that record, and the
    record's project attributes the session. A session that touched nothing
    lands under ``unattributed`` rather than being dropped -- an allocated
    session that never wrote is exactly the signal a session-volume chart
    should show.
    """
    touched: Dict[str, Set[Tuple[str, str]]] = defaultdict(set)
    for record in corpus.records:
        item_id = record.get("item_id") or str(record.get("record_id", "")).split("#")[-1]
        project = record.get("project_id") or ""
        for session_id in sessions_in_history(record):
            touched[session_id].add((project, item_id))

    types = corpus.agent_type_index
    buckets: Dict[Tuple[date, str, str, str], Dict[str, Set[str]]] = defaultdict(
        lambda: {"sessions": set(), "records": set()}
    )

    for session in corpus.sessions:
        session_id = session.get("session_id")
        day = to_date(session.get("created_at"))
        if not session_id or not day:
            continue
        agent_type_id = str(session.get("agent_type_id") or "")
        dimension = types.get(agent_type_id, {})
        agent_type = dimension.get("surface") or agent_type_id or "unknown"
        model = dimension.get("model") or "unknown"

        pairs = touched.get(session_id) or set()
        if not pairs:
            bucket = buckets[(day, "unattributed", agent_type, model)]
            bucket["sessions"].add(session_id)
            continue
        by_project: Dict[str, Set[str]] = defaultdict(set)
        for project, record_id in pairs:
            by_project[project].add(record_id)
        for project, record_ids in by_project.items():
            bucket = buckets[(day, project, agent_type, model)]
            bucket["sessions"].add(session_id)
            bucket["records"].update(record_ids)

    return [
        {
            "snapshot_date": day,
            "project_id": project,
            "agent_type": agent_type,
            "model": model,
            "session_count": len(values["sessions"]),
            "records_touched": len(values["records"]),
        }
        for (day, project, agent_type, model), values in sorted(
            buckets.items(), key=lambda pair: (pair[0][0], pair[0][1], pair[0][2], pair[0][3])
        )
    ]


# --- graph -----------------------------------------------------------------

#: Tracker fields that declare an edge to another governed node.
_RECORD_EDGE_FIELDS = (
    "parent", "primary_task", "subtask_ids", "related_task_ids",
    "related_issue_ids", "related_feature_ids", "related_plan_ids",
    "related_items", "informed_by",
)
_DOCUMENT_EDGE_FIELDS = ("related_items", "informed_by")


def _edge_targets(item: Mapping[str, Any], fields: Sequence[str]) -> List[str]:
    targets: List[str] = []
    for field in fields:
        value = item.get(field)
        if not value:
            continue
        if isinstance(value, str):
            targets.append(value)
        elif isinstance(value, list):
            targets.extend(str(entry) for entry in value if entry)
    return targets


def build_fact_graph_health_daily(corpus, last_day: date) -> List[Dict[str, Any]]:
    """DVP-TSK-678. One row per snapshot_date.

    The first four columns are computed from the governed graph itself. The
    last four are DECLARED AND NULL: their upstream does not exist yet
    (``graph_health_metrics`` publishes CloudWatch proxies and says in its own
    docstring that it substitutes them "instead of native Fiedler lambda-2
    computation"), and DVP-TSK-678 AC-5 puts the metric computation out of
    scope here. Declaring them now means ENC-FTR-063 fills a column rather than
    negotiating a schema change against a live table.
    """
    born: Dict[str, date] = {}
    for record in corpus.records:
        item_id = record.get("item_id") or str(record.get("record_id", "")).split("#")[-1]
        day = to_date(record.get("created_at"))
        if item_id and day:
            born[item_id] = day
    for document in corpus.documents:
        document_id = document.get("document_id")
        day = to_date(document.get("created_at"))
        if document_id and day:
            born[document_id] = day

    if not born:
        return []

    # Edges become RESOLVABLE on the later of their endpoints' creation dates;
    # an edge whose target is not a governed node is UNRESOLVED from the moment
    # its source exists. Both are then cumulative counts by date, so the whole
    # per-day series is prefix sums rather than a per-day graph walk.
    resolvable_on: Dict[date, int] = defaultdict(int)
    unresolved_on: Dict[date, int] = defaultdict(int)
    first_edge: Dict[str, date] = {}

    def _note(source: str, target: str) -> None:
        source_day = born.get(source)
        if not source_day:
            return
        target_day = born.get(target)
        if target_day is None:
            unresolved_on[source_day] += 1
            return
        day = max(source_day, target_day)
        resolvable_on[day] += 1
        for node in (source, target):
            if node not in first_edge or day < first_edge[node]:
                first_edge[node] = day

    for record in corpus.records:
        source = record.get("item_id") or str(record.get("record_id", "")).split("#")[-1]
        if not source:
            continue
        for target in _edge_targets(record, _RECORD_EDGE_FIELDS):
            _note(source, target)
    for document in corpus.documents:
        source = document.get("document_id")
        if not source:
            continue
        for target in _edge_targets(document, _DOCUMENT_EDGE_FIELDS):
            _note(source, target)

    born_on: Dict[date, int] = defaultdict(int)
    for day in born.values():
        born_on[day] += 1
    connected_on: Dict[date, int] = defaultdict(int)
    for day in first_edge.values():
        connected_on[day] += 1

    first_day = min(born.values())
    nodes = edges = unresolved = connected = 0
    rows: List[Dict[str, Any]] = []
    for day in date_range(first_day, last_day):
        nodes += born_on.get(day, 0)
        edges += resolvable_on.get(day, 0)
        unresolved += unresolved_on.get(day, 0)
        connected += connected_on.get(day, 0)
        rows.append(
            {
                "snapshot_date": day,
                "node_count": nodes,
                "edge_count": edges,
                "orphan_node_count": nodes - connected,
                "unresolved_edge_count": unresolved,
                # Declared now, populated incrementally (risk R-11).
                "hot_tier_fraction": None,
                "percolation_margin": None,
                "fiedler_value": None,
                "demand_centroid_drift": None,
            }
        )
    return rows


# ---------------------------------------------------------------------------
# One pass
# ---------------------------------------------------------------------------


def build_all(corpus, last_day: Optional[date] = None) -> Dict[str, List[Dict[str, Any]]]:
    """Project every declared mart table from one corpus read."""
    if last_day is None:
        last_day = datetime.now(timezone.utc).date()
    return {
        "dim_record": build_dim_record(corpus),
        "fact_record_daily": build_fact_record_daily(corpus, last_day),
        "fact_record_transition": build_fact_record_transition(corpus),
        "dim_document": build_dim_document(corpus),
        "fact_document_daily": build_fact_document_daily(corpus, last_day),
        "fact_session_daily": build_fact_session_daily(corpus),
        "fact_graph_health_daily": build_fact_graph_health_daily(corpus, last_day),
    }
