"""Unit tests for feed_query incremental delta behavior."""

from __future__ import annotations

import importlib.util
import json
import os


_SPEC = importlib.util.spec_from_file_location(
    "feed_query_lambda",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
feed_query = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(feed_query)


def _feed_get_event(since: str) -> dict:
    return {
        "requestContext": {"http": {"method": "GET"}},
        "rawPath": "/api/v1/feed",
        "headers": {"Cookie": "enceladus_id_token=test-token"},
        "queryStringParameters": {"since": since},
    }


def test_since_delta_applies_lookback_and_returns_no_cache(monkeypatch):
    monkeypatch.setattr(feed_query, "_verify_token", lambda _token: {"sub": "u-1"})

    captured = {}

    def _fake_query_incremental(since_iso: str):
        captured["since_iso"] = since_iso
        # Returns (tasks, issues, features, lessons, plans, closed_ids).
        # Plans were added in ENC-FTR-058 (ed65d01); keeping the tuple shape
        # in sync with the real function signature.
        return [], [], [], [], [], ["ENC-TSK-123"]

    monkeypatch.setattr(feed_query, "_query_incremental", _fake_query_incremental)

    resp = feed_query.lambda_handler(_feed_get_event("2026-02-25T12:00:10Z"), None)

    assert resp["statusCode"] == 200
    assert captured["since_iso"] == "2026-02-25T12:00:00Z"
    assert resp["headers"]["Cache-Control"] == "no-cache, no-store, must-revalidate"
    payload = json.loads(resp["body"])
    assert payload["closed_ids"] == ["ENC-TSK-123"]
    # Delta payload must also surface plans and lessons keys, even when empty,
    # so the PWA LiveFeedContext can reliably read data.lessons / data.plans.
    assert "lessons" in payload
    assert "plans" in payload


def test_invalid_since_returns_400(monkeypatch):
    monkeypatch.setattr(feed_query, "_verify_token", lambda _token: {"sub": "u-1"})

    resp = feed_query.lambda_handler(_feed_get_event("not-a-date"), None)

    assert resp["statusCode"] == 400
    payload = json.loads(resp["body"])
    assert "since" in payload["error"]


def _corpus_get_event(**params: str) -> dict:
    return {
        "requestContext": {"http": {"method": "GET"}},
        "rawPath": "/api/v1/feed/corpus",
        "headers": {"Cookie": "enceladus_id_token=test-token"},
        "queryStringParameters": params or None,
    }


def test_corpus_requires_auth():
    resp = feed_query.lambda_handler(
        {
            "requestContext": {"http": {"method": "GET"}},
            "rawPath": "/api/v1/feed/corpus",
            "headers": {},
        },
        None,
    )
    assert resp["statusCode"] == 401


def test_corpus_returns_paginated_payload(monkeypatch):
    monkeypatch.setattr(feed_query, "_verify_token", lambda _token: {"sub": "u-1"})
    monkeypatch.setattr(
        feed_query,
        "_get_corpus_entries",
        lambda: feed_query.feed_corpus.build_tracker_entries_from_records(
            [{"task_id": "ENC-TSK-1", "project_id": "enceladus", "title": "One", "status": "open", "priority": "P1", "updated_at": "2026-07-05T10:00:00Z"}],
            [],
            [],
            [],
            [],
        ),
    )

    resp = feed_query.lambda_handler(_corpus_get_event(limit="10"), None)
    assert resp["statusCode"] == 200
    payload = json.loads(resp["body"])
    assert payload["success"] is True
    assert payload["items"][0]["record_id"] == "ENC-TSK-1"
    assert "facets" in payload
    assert payload["total_matches"] == 1


def test_corpus_invalid_cursor_returns_400(monkeypatch):
    monkeypatch.setattr(feed_query, "_verify_token", lambda _token: {"sub": "u-1"})
    resp = feed_query.lambda_handler(_corpus_get_event(cursor="bad-cursor"), None)
    assert resp["statusCode"] == 400


# ---------------------------------------------------------------------------
# _ddb_history defensive behavior (ENC-TSK-C31)
#
# PR #239 (commit a4b3751) introduced _ddb_history() and started calling it
# from all five _transform_*_from_ddb helpers. A crash in _ddb_history for
# any single record propagated out of _query_all_records and returned HTTP
# 500 for the full-refresh /api/v1/feed endpoint. In the PWA, doFullRefresh
# caught the 500 as a generic error, leaving hasLiveSnapshot=false; tasks,
# issues, and features fell back to S3 (still visible) but lessons and
# plans have no S3 fallback in useFeed.ts and collapsed to empty arrays —
# which is exactly the ENC-ISS-176 / ENC-TSK-C29 / ENC-TSK-C31 symptom.
#
# These tests lock in that _ddb_history tolerates every input shape we
# have observed or can reasonably imagine DynamoDB serving.
# ---------------------------------------------------------------------------


def test_ddb_history_missing_attribute_returns_empty():
    item = {"item_id": {"S": "ENC-TSK-123"}}
    assert feed_query._ddb_history(item) == []


def test_ddb_history_none_attribute_returns_empty():
    # Attribute key present but value is None (not a DDB wire-format dict).
    # Prior bug: `item.get("history", {})` returns None when the key exists,
    # then `None.get("L")` raised AttributeError and crashed the transform.
    item = {"item_id": {"S": "ENC-TSK-123"}, "history": None}
    assert feed_query._ddb_history(item) == []


def test_ddb_history_non_dict_attribute_returns_empty():
    item = {"item_id": {"S": "ENC-TSK-123"}, "history": "not-a-dict"}
    assert feed_query._ddb_history(item) == []


def test_ddb_history_non_list_l_value_returns_empty():
    item = {"item_id": {"S": "ENC-TSK-123"}, "history": {"L": "not-a-list"}}
    assert feed_query._ddb_history(item) == []


def test_ddb_history_empty_list_returns_empty():
    item = {"item_id": {"S": "ENC-TSK-123"}, "history": {"L": []}}
    assert feed_query._ddb_history(item) == []


def test_ddb_history_non_dict_entry_skipped():
    item = {
        "item_id": {"S": "ENC-TSK-123"},
        "history": {"L": ["not-a-dict", 42, None]},
    }
    assert feed_query._ddb_history(item) == []


def test_ddb_history_entry_missing_m_skipped():
    item = {
        "item_id": {"S": "ENC-TSK-123"},
        "history": {"L": [{"S": "wrong-type-marker"}]},
    }
    assert feed_query._ddb_history(item) == []


def test_ddb_history_entry_with_m_none_skipped():
    # The exact shape that most likely caused the live 500: entry["M"] is
    # None (rather than a dict). Prior code did `m = entry["M"]` then
    # `m.get("timestamp", {})` which raised AttributeError on None.
    item = {
        "item_id": {"S": "ENC-TSK-123"},
        "history": {"L": [{"M": None}]},
    }
    assert feed_query._ddb_history(item) == []


def test_ddb_history_entry_with_empty_m_normalized():
    item = {
        "item_id": {"S": "ENC-TSK-123"},
        "history": {"L": [{"M": {}}]},
    }
    assert feed_query._ddb_history(item) == [
        {"timestamp": "", "status": "", "description": ""}
    ]


def test_ddb_history_field_value_is_bare_string():
    # The inner field ("timestamp") is stored as a bare string instead of a
    # {'S': ...} wire-format dict. Prior code did
    # `m.get("timestamp", {}).get("S", "")` and crashed with AttributeError
    # on the bare string.
    item = {
        "item_id": {"S": "ENC-TSK-123"},
        "history": {
            "L": [
                {
                    "M": {
                        "timestamp": "raw-string",
                        "status": {"S": "created"},
                        "description": {"S": "ok"},
                    }
                }
            ]
        },
    }
    assert feed_query._ddb_history(item) == [
        {"timestamp": "", "status": "created", "description": "ok"}
    ]


def test_ddb_history_field_s_value_not_string():
    # Extremely defensive: S field with a non-string nested value.
    item = {
        "item_id": {"S": "ENC-TSK-123"},
        "history": {
            "L": [
                {
                    "M": {
                        "timestamp": {"S": 12345},
                        "status": {"S": "ok"},
                        "description": {"S": None},
                    }
                }
            ]
        },
    }
    assert feed_query._ddb_history(item) == [
        {"timestamp": "", "status": "ok", "description": ""}
    ]


def test_ddb_history_normal_entry_extracted():
    item = {
        "item_id": {"S": "ENC-TSK-123"},
        "history": {
            "L": [
                {
                    "M": {
                        "timestamp": {"S": "2026-04-07T11:00:00Z"},
                        "status": {"S": "created"},
                        "description": {"S": "Task created via API"},
                    }
                },
                {
                    "M": {
                        "timestamp": {"S": "2026-04-07T11:05:00Z"},
                        "status": {"S": "in-progress"},
                        "description": {"S": "Checked out"},
                    }
                },
            ]
        },
    }
    result = feed_query._ddb_history(item)
    assert len(result) == 2
    assert result[0]["status"] == "created"
    assert result[1]["status"] == "in-progress"
    assert result[1]["description"] == "Checked out"


def test_ddb_history_caps_at_max_entries():
    # ENC-TSK-C34: MAX_HISTORY_ENTRIES reduced from 50 to 10 as a secondary
    # guardrail against the Lambda 6 MB sync response limit. The primary
    # guardrail is the per-type record cap in _query_all_records.
    assert feed_query.MAX_HISTORY_ENTRIES == 10
    entries = [
        {
            "M": {
                "timestamp": {"S": f"2026-04-07T11:00:{i:02d}Z"},
                "status": {"S": "worklog"},
                "description": {"S": f"entry {i}"},
            }
        }
        for i in range(feed_query.MAX_HISTORY_ENTRIES + 10)
    ]
    item = {"item_id": {"S": "ENC-TSK-123"}, "history": {"L": entries}}
    result = feed_query._ddb_history(item)
    assert len(result) == feed_query.MAX_HISTORY_ENTRIES
    # Keeps the most recent (tail-end) entries.
    assert result[-1]["description"] == f"entry {feed_query.MAX_HISTORY_ENTRIES + 9}"


# ---------------------------------------------------------------------------
# _cap_by_updated_at per-type response cap (ENC-TSK-C34)
#
# The full /api/v1/feed response is a single synchronous Lambda payload and
# must fit under AWS Lambda's 6 MB sync response limit. With history arrays
# populated per-record (ENC-TSK-C01), the pre-cap response exceeded that
# limit and returned the opaque {"message":"Internal Server Error"} from
# Lambda runtime, which broke PWA plan + lesson rendering (they have no S3
# fallback in useFeed.ts). The fix is a per-type cap applied inside
# _query_all_records: tasks=100, issues/features/lessons/plans=10 each.
# ---------------------------------------------------------------------------


def test_cap_by_updated_at_short_list_unchanged():
    records = [{"task_id": f"T-{i}", "updated_at": f"2026-04-07T00:00:{i:02d}Z"} for i in range(3)]
    result = feed_query._cap_by_updated_at(records, 100)
    assert result == records
    assert result is records  # Unchanged = same reference.


def test_cap_by_updated_at_exactly_at_cap_unchanged():
    records = [{"task_id": f"T-{i}", "updated_at": f"2026-04-07T00:00:{i:02d}Z"} for i in range(10)]
    result = feed_query._cap_by_updated_at(records, 10)
    assert result == records
    assert result is records


def test_cap_by_updated_at_truncates_to_most_recent():
    records = [
        {"task_id": f"T-{i}", "updated_at": f"2026-04-{(i % 28) + 1:02d}T00:00:00Z"}
        for i in range(20)
    ]
    result = feed_query._cap_by_updated_at(records, 5)
    assert len(result) == 5
    # All kept records must have higher (more recent) updated_at than any
    # dropped record.
    kept_ts = {r["updated_at"] for r in result}
    dropped_ts = {r["updated_at"] for r in records if r not in result}
    assert min(kept_ts) >= max(dropped_ts)


def test_cap_by_updated_at_none_updated_at_sorts_last():
    # Records with missing / None / empty updated_at are the first to be
    # dropped when the cap is exceeded.
    records = [
        {"task_id": "T-old-1", "updated_at": None},
        {"task_id": "T-fresh-a", "updated_at": "2026-04-07T10:00:00Z"},
        {"task_id": "T-old-2", "updated_at": ""},
        {"task_id": "T-fresh-b", "updated_at": "2026-04-06T10:00:00Z"},
        {"task_id": "T-old-3"},  # missing key entirely
    ]
    result = feed_query._cap_by_updated_at(records, 2)
    kept_ids = {r["task_id"] for r in result}
    assert kept_ids == {"T-fresh-a", "T-fresh-b"}


def test_cap_by_updated_at_zero_cap_returns_unchanged():
    # Defensive: cap=0 is treated as "no cap" so the caller does not
    # accidentally wipe the list by passing an uninitialized constant.
    records = [{"task_id": "T-1", "updated_at": "2026-04-07T00:00:00Z"}]
    assert feed_query._cap_by_updated_at(records, 0) == records


def test_max_full_refresh_caps_configured():
    # ENC-TSK-C34: Lock in the per-type cap contract with the PWA
    # (FeedPage.tsx useInfiniteList(items, 20, 100)).
    assert feed_query.MAX_TASKS_FULL_REFRESH == 100
    assert feed_query.MAX_ISSUES_FULL_REFRESH == 10
    assert feed_query.MAX_FEATURES_FULL_REFRESH == 10
    assert feed_query.MAX_LESSONS_FULL_REFRESH == 10
    assert feed_query.MAX_PLANS_FULL_REFRESH == 10


# ---------------------------------------------------------------------------
# Per-project fan-out + per-project caps (ENC-TSK-M36 / feed data-truth)
#
# Confirmed live against gamma: /api/v1/feed/tasks.json and /api/v1/feed/corpus
# both took ~20s on a cache miss because _query_all_records / (the former
# _query_corpus_tracker_records copy) queried every active project's
# project-type-index SEQUENTIALLY. Separately, the per-type caps used to
# apply to the merged cross-project pool, so a project with many lessons
# recently updated could crowd another project's lessons out of the snapshot
# entirely even though that project's lessons were never actually missing
# from DynamoDB. _fan_out_by_project fixes the latency (concurrent per-
# project fetch); capping inside _query_all_records's per-project loop fixes
# the fairness -- these tests lock in both behaviors without touching
# DynamoDB (project fetch itself is monkeypatched).
# ---------------------------------------------------------------------------


def _fake_project_records(pid: str, lesson_count: int) -> tuple:
    """Build a one-project (tasks, issues, features, lessons, plans) tuple
    with `lesson_count` lessons, each with a distinct recent updated_at so
    _cap_by_updated_at's ordering is deterministic."""
    lessons = [
        {
            "lesson_id": f"{pid}-LSN-{i:03d}",
            "project_id": pid,
            "updated_at": f"2026-07-0{(i % 8) + 1}T00:00:00Z",
        }
        for i in range(lesson_count)
    ]
    return ([], [], [], lessons, [])


def test_fan_out_by_project_queries_every_project_and_preserves_order(monkeypatch):
    projects = [{"project_id": "enceladus"}, {"project_id": "cfg"}, {"project_id": "fly"}]
    calls: list[str] = []

    def fake_query(pid, _cutoff):
        calls.append(pid)
        return _fake_project_records(pid, lesson_count=1)

    monkeypatch.setattr(feed_query, "_query_project_tracker_records", fake_query)
    cutoff = feed_query.dt.datetime.now(feed_query.dt.timezone.utc)
    results = feed_query._fan_out_by_project(projects, cutoff)

    # Every project was queried exactly once...
    assert sorted(calls) == ["cfg", "enceladus", "fly"]
    # ...and results come back in the SAME order as the input project list,
    # regardless of thread completion order.
    assert [pid for pid, _ in results] == ["enceladus", "cfg", "fly"]


def test_fan_out_by_project_empty_list_short_circuits(monkeypatch):
    called = False

    def fake_query(_pid, _cutoff):
        nonlocal called
        called = True
        return ([], [], [], [], [])

    monkeypatch.setattr(feed_query, "_query_project_tracker_records", fake_query)
    cutoff = feed_query.dt.datetime.now(feed_query.dt.timezone.utc)
    assert feed_query._fan_out_by_project([], cutoff) == []
    assert called is False


def test_query_all_records_caps_are_per_project_not_global(monkeypatch):
    # A busier project ("enceladus") has 15 lessons (over the cap of 10); a
    # quieter project ("cfg") has 2. Before ENC-TSK-M36, the cap applied to
    # the MERGED 17-lesson pool, so with a global cap of 10 the two "cfg"
    # lessons could be entirely dropped if enceladus's lessons all sorted
    # more recent. Capping per project must keep BOTH projects represented.
    monkeypatch.setattr(
        feed_query,
        "_get_active_projects",
        lambda: [{"project_id": "enceladus"}, {"project_id": "cfg"}],
    )

    def fake_query(pid, _cutoff):
        if pid == "enceladus":
            return _fake_project_records(pid, lesson_count=15)
        return _fake_project_records(pid, lesson_count=2)

    monkeypatch.setattr(feed_query, "_query_project_tracker_records", fake_query)

    _tasks, _issues, _features, all_lessons, _plans = feed_query._query_all_records()

    lesson_ids = {l["lesson_id"] for l in all_lessons}
    # enceladus capped down to 10 (its own cap, not zeroed out by cfg)...
    assert sum(1 for lid in lesson_ids if lid.startswith("enceladus-")) == 10
    # ...and cfg's 2 lessons survive too -- global capping would have let
    # enceladus's 15 crowd them out entirely.
    assert sum(1 for lid in lesson_ids if lid.startswith("cfg-")) == 2


# ---------------------------------------------------------------------------
# VALID_RECORD_TYPES whitelist (ENC-TSK-C40 / ENC-ISS-177)
#
# Before the fix, VALID_RECORD_TYPES = {"task", "issue", "feature"} silently
# dropped 'lesson' and 'plan' from subscription-scoped feeds. The feed
# pipeline already transforms lessons and plans via _TRANSFORM, so the
# whitelist was stale relative to the real record-type surface. These
# regression tests lock in the corrected whitelist and assert that plan
# and lesson records survive _normalize_scope and _apply_subscription_scope
# filtering.
# ---------------------------------------------------------------------------


def test_valid_record_types_includes_lesson_and_plan():
    # Whitelist must match the actual _TRANSFORM record-type surface.
    assert "lesson" in feed_query.VALID_RECORD_TYPES
    assert "plan" in feed_query.VALID_RECORD_TYPES
    assert feed_query.VALID_RECORD_TYPES == {"task", "issue", "feature", "lesson", "plan"}


def test_normalize_scope_preserves_plan_record_type():
    scope = {"record_types": ["plan"]}
    normalized = feed_query._normalize_scope(scope, None)
    assert normalized["record_types"] == ["plan"]


def test_normalize_scope_preserves_lesson_record_type():
    scope = {"record_types": ["lesson"]}
    normalized = feed_query._normalize_scope(scope, None)
    assert normalized["record_types"] == ["lesson"]


def test_normalize_scope_preserves_all_five_record_types():
    scope = {"record_types": ["task", "issue", "feature", "lesson", "plan"]}
    normalized = feed_query._normalize_scope(scope, None)
    assert set(normalized["record_types"]) == {
        "task",
        "issue",
        "feature",
        "lesson",
        "plan",
    }


def test_normalize_scope_drops_unknown_record_type():
    # Defensive: anything outside the whitelist is still filtered out.
    scope = {"record_types": ["plan", "bogus", "LESSON", "worklog"]}
    normalized = feed_query._normalize_scope(scope, None)
    # Case-folded; bogus and worklog dropped.
    assert set(normalized["record_types"]) == {"plan", "lesson"}


def _mock_records():
    return {
        "tasks": [
            {"task_id": "ENC-TSK-900", "project_id": "enceladus", "status": "open", "updated_at": "2026-04-07T10:00:00Z"},
        ],
        "issues": [
            {"issue_id": "ENC-ISS-900", "project_id": "enceladus", "status": "open", "updated_at": "2026-04-07T10:00:00Z"},
        ],
        "features": [
            {"feature_id": "ENC-FTR-900", "project_id": "enceladus", "status": "planned", "updated_at": "2026-04-07T10:00:00Z"},
        ],
        "lessons": [
            {"lesson_id": "ENC-LSN-900", "project_id": "enceladus", "status": "active", "updated_at": "2026-04-07T10:00:00Z"},
        ],
        "plans": [
            {"plan_id": "ENC-PLN-900", "project_id": "enceladus", "status": "started", "updated_at": "2026-04-07T10:00:00Z"},
        ],
    }


def test_apply_subscription_scope_plan_only_keeps_plans():
    records = _mock_records()
    subscription = {"scope": {"record_types": ["plan"]}}
    (
        scoped_tasks,
        scoped_issues,
        scoped_features,
        scoped_lessons,
        scoped_plans,
        matched,
    ) = feed_query._apply_subscription_scope(
        records["tasks"],
        records["issues"],
        records["features"],
        records["lessons"],
        records["plans"],
        subscription,
    )
    assert scoped_tasks == []
    assert scoped_issues == []
    assert scoped_features == []
    assert scoped_lessons == []
    assert len(scoped_plans) == 1
    assert scoped_plans[0]["plan_id"] == "ENC-PLN-900"
    assert matched == 1


def test_apply_subscription_scope_lesson_only_keeps_lessons():
    records = _mock_records()
    subscription = {"scope": {"record_types": ["lesson"]}}
    (
        scoped_tasks,
        scoped_issues,
        scoped_features,
        scoped_lessons,
        scoped_plans,
        matched,
    ) = feed_query._apply_subscription_scope(
        records["tasks"],
        records["issues"],
        records["features"],
        records["lessons"],
        records["plans"],
        subscription,
    )
    assert scoped_tasks == []
    assert scoped_issues == []
    assert scoped_features == []
    assert scoped_plans == []
    assert len(scoped_lessons) == 1
    assert scoped_lessons[0]["lesson_id"] == "ENC-LSN-900"
    assert matched == 1


def test_apply_subscription_scope_empty_record_types_keeps_everything():
    # An empty/unspecified record_types list must NOT filter anything out.
    records = _mock_records()
    subscription = {"scope": {"record_types": []}}
    (
        scoped_tasks,
        scoped_issues,
        scoped_features,
        scoped_lessons,
        scoped_plans,
        matched,
    ) = feed_query._apply_subscription_scope(
        records["tasks"],
        records["issues"],
        records["features"],
        records["lessons"],
        records["plans"],
        subscription,
    )
    assert len(scoped_tasks) == 1
    assert len(scoped_issues) == 1
    assert len(scoped_features) == 1
    assert len(scoped_lessons) == 1
    assert len(scoped_plans) == 1
    assert matched == 5


def test_apply_subscription_scope_mixed_types_keeps_selected():
    records = _mock_records()
    subscription = {"scope": {"record_types": ["task", "plan"]}}
    (
        scoped_tasks,
        scoped_issues,
        scoped_features,
        scoped_lessons,
        scoped_plans,
        matched,
    ) = feed_query._apply_subscription_scope(
        records["tasks"],
        records["issues"],
        records["features"],
        records["lessons"],
        records["plans"],
        subscription,
    )
    assert len(scoped_tasks) == 1
    assert scoped_issues == []
    assert scoped_features == []
    assert scoped_lessons == []
    assert len(scoped_plans) == 1
    assert matched == 2


def test_ddb_history_mixed_good_and_bad_entries():
    # A single bad entry must not poison the whole history array.
    item = {
        "item_id": {"S": "ENC-TSK-123"},
        "history": {
            "L": [
                {
                    "M": {
                        "timestamp": {"S": "2026-04-07T11:00:00Z"},
                        "status": {"S": "created"},
                        "description": {"S": "good entry 1"},
                    }
                },
                {"M": None},  # bad: M is None
                "not-a-dict",  # bad: not a dict
                {
                    "M": {
                        "timestamp": {"S": "2026-04-07T11:05:00Z"},
                        "status": {"S": "worklog"},
                        "description": {"S": "good entry 2"},
                    }
                },
            ]
        },
    }
    result = feed_query._ddb_history(item)
    assert len(result) == 2
    assert result[0]["description"] == "good entry 1"
    assert result[1]["description"] == "good entry 2"


# ---------------------------------------------------------------------------
# ENC-TSK-M39: OpenSearch-tier fast path + DDB circuit-breaker fallback
#
# feed_query is not VPC-attached to the OpenSearch domain, so the fast path
# invokes graph_query_api (action='feed_selection', already VPC-attached) as
# a selection proxy, then hydrates the returned record keys with the same
# bounded BatchGetItem helper the incremental/delta path already uses. Any
# failure (missing config, invoke error, non-ok response) must fall back to
# the existing DDB fan-out rather than raising or returning nothing.
# ---------------------------------------------------------------------------


class _FakePayload:
    def __init__(self, payload: dict):
        self._body = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._body


class _FakeGraphQueryLambdaClient:
    def __init__(self, response=None, exc=None):
        self._response = response
        self._exc = exc
        self.calls: list[dict] = []

    def invoke(self, **kwargs):
        self.calls.append(kwargs)
        if self._exc is not None:
            raise self._exc
        return self._response


def test_query_all_records_via_opensearch_disabled_when_function_unset(monkeypatch):
    monkeypatch.setattr(feed_query, "GRAPH_QUERY_API_FUNCTION", "")
    result = feed_query._query_all_records_via_opensearch(
        [{"project_id": "enceladus"}], feed_query.dt.datetime.now(feed_query.dt.timezone.utc)
    )
    assert result is None


def test_query_all_records_via_opensearch_returns_none_on_invoke_error(monkeypatch):
    monkeypatch.setattr(feed_query, "GRAPH_QUERY_API_FUNCTION", "devops-graph-query-api-gamma")
    fake_client = _FakeGraphQueryLambdaClient(exc=feed_query.ClientError({"Error": {}}, "Invoke"))
    monkeypatch.setattr(feed_query, "_get_graph_query_lambda_client", lambda: fake_client)

    result = feed_query._query_all_records_via_opensearch(
        [{"project_id": "enceladus"}], feed_query.dt.datetime.now(feed_query.dt.timezone.utc)
    )
    assert result is None
    assert len(fake_client.calls) == 1


def test_query_all_records_via_opensearch_returns_none_when_not_ok(monkeypatch):
    monkeypatch.setattr(feed_query, "GRAPH_QUERY_API_FUNCTION", "devops-graph-query-api-gamma")
    fake_client = _FakeGraphQueryLambdaClient(
        response={"Payload": _FakePayload({"ok": False, "error": "opensearch_not_configured"})}
    )
    monkeypatch.setattr(feed_query, "_get_graph_query_lambda_client", lambda: fake_client)

    result = feed_query._query_all_records_via_opensearch(
        [{"project_id": "enceladus"}], feed_query.dt.datetime.now(feed_query.dt.timezone.utc)
    )
    assert result is None


def test_query_all_records_via_opensearch_returns_none_on_function_error(monkeypatch):
    monkeypatch.setattr(feed_query, "GRAPH_QUERY_API_FUNCTION", "devops-graph-query-api-gamma")
    fake_client = _FakeGraphQueryLambdaClient(
        response={"Payload": _FakePayload({"ok": True, "selection": {}}), "FunctionError": "Unhandled"}
    )
    monkeypatch.setattr(feed_query, "_get_graph_query_lambda_client", lambda: fake_client)

    result = feed_query._query_all_records_via_opensearch(
        [{"project_id": "enceladus"}], feed_query.dt.datetime.now(feed_query.dt.timezone.utc)
    )
    assert result is None


# ---------------------------------------------------------------------------
# ENC-TSK-M48: _hydrate_records_via_batch_get fans out concurrently
#
# Live gamma verification of M39/M47 showed feed_source=opensearch but ~4s
# p95, not <500ms -- CloudWatch confirmed graph_query_api's own selection
# round trip was already fast, isolating the bottleneck to feed_query's own
# sequential BatchGetItem chunking across the (often 20+ active project)
# candidate set the OpenSearch tier can return. These tests lock in that the
# fix fans batches out via a thread pool (matching ENC-TSK-M36's DDB fan-out
# concurrency fix) rather than one call at a time.
# ---------------------------------------------------------------------------


def test_hydrate_records_via_batch_get_empty_short_circuits(monkeypatch):
    called = False

    def fake_fetch(_batch, _cutoff):
        nonlocal called
        called = True
        return ([], [], [], [], [], [])

    monkeypatch.setattr(feed_query, "_fetch_and_transform_batch", fake_fetch)
    cutoff = feed_query.dt.datetime.now(feed_query.dt.timezone.utc)
    assert feed_query._hydrate_records_via_batch_get([], cutoff) == ([], [], [], [], [], [])
    assert called is False


def test_hydrate_records_via_batch_get_chunks_concurrently_and_merges(monkeypatch):
    # 250 keys -> 3 chunks of <=100 -- forces _hydrate_records_via_batch_get
    # to fan out more than one batch.
    changed_keys = [
        {"project_id": {"S": "enceladus"}, "record_id": {"S": f"task#T-{i}"}}
        for i in range(250)
    ]
    seen_batch_sizes = []

    def fake_fetch(batch, _cutoff):
        seen_batch_sizes.append(len(batch))
        # One distinct task per batch so we can confirm every batch's
        # results made it into the merged output.
        rid = batch[0]["record_id"]["S"]
        return ([{"task_id": rid}], [], [], [], [], [])

    monkeypatch.setattr(feed_query, "_fetch_and_transform_batch", fake_fetch)
    cutoff = feed_query.dt.datetime.now(feed_query.dt.timezone.utc)

    tasks, issues, features, lessons, plans, closed_ids = feed_query._hydrate_records_via_batch_get(
        changed_keys, cutoff
    )

    assert sorted(seen_batch_sizes) == [50, 100, 100]
    assert len(tasks) == 3
    assert issues == [] and features == [] and lessons == [] and plans == [] and closed_ids == []


def test_query_all_records_via_opensearch_no_active_projects_short_circuits(monkeypatch):
    monkeypatch.setattr(feed_query, "GRAPH_QUERY_API_FUNCTION", "devops-graph-query-api-gamma")
    fake_client = _FakeGraphQueryLambdaClient()
    monkeypatch.setattr(feed_query, "_get_graph_query_lambda_client", lambda: fake_client)

    result = feed_query._query_all_records_via_opensearch(
        [], feed_query.dt.datetime.now(feed_query.dt.timezone.utc)
    )
    assert result == ([], [], [], [], [])
    assert fake_client.calls == []  # never invokes with an empty project list


def test_query_all_records_via_opensearch_hydrates_selected_keys(monkeypatch):
    monkeypatch.setattr(feed_query, "GRAPH_QUERY_API_FUNCTION", "devops-graph-query-api-gamma")
    selection = {
        "enceladus#task": ["ENC-TSK-001", "ENC-TSK-002"],
        "enceladus#issue": ["ENC-ISS-010"],
    }
    fake_client = _FakeGraphQueryLambdaClient(
        response={"Payload": _FakePayload({"ok": True, "selection": selection})}
    )
    monkeypatch.setattr(feed_query, "_get_graph_query_lambda_client", lambda: fake_client)

    captured = {}

    def fake_hydrate(changed_keys, _cutoff):
        captured["keys"] = changed_keys
        return (["task-row"], ["issue-row"], [], [], [], [])

    monkeypatch.setattr(feed_query, "_hydrate_records_via_batch_get", fake_hydrate)

    result = feed_query._query_all_records_via_opensearch(
        [{"project_id": "enceladus"}], feed_query.dt.datetime.now(feed_query.dt.timezone.utc)
    )

    assert result == (["task-row"], ["issue-row"], [], [], [])
    # Invoke payload carries the per-type caps + active project IDs.
    invoke_payload = json.loads(fake_client.calls[0]["Payload"])
    assert invoke_payload["action"] == "feed_selection"
    assert invoke_payload["project_ids"] == ["enceladus"]
    assert invoke_payload["caps"]["task"] == feed_query.MAX_TASKS_FULL_REFRESH
    # Selected bare IDs are reconstructed into (project_id, record_id) DDB keys.
    assert {"project_id": {"S": "enceladus"}, "record_id": {"S": "task#ENC-TSK-001"}} in captured["keys"]
    assert {"project_id": {"S": "enceladus"}, "record_id": {"S": "task#ENC-TSK-002"}} in captured["keys"]
    assert {"project_id": {"S": "enceladus"}, "record_id": {"S": "issue#ENC-ISS-010"}} in captured["keys"]


def test_query_all_records_uses_opensearch_result_when_available(monkeypatch):
    monkeypatch.setattr(feed_query, "_get_active_projects", lambda: [{"project_id": "enceladus"}])
    monkeypatch.setattr(
        feed_query,
        "_query_all_records_via_opensearch",
        lambda _projects, _cutoff: (["t"], ["i"], ["f"], ["l"], ["p"]),
    )

    def _boom(*_a, **_k):
        raise AssertionError("DDB fallback must not run when the OpenSearch tier succeeds")

    monkeypatch.setattr(feed_query, "_query_all_records_via_ddb", _boom)

    result = feed_query._query_all_records()
    assert result == (["t"], ["i"], ["f"], ["l"], ["p"])
    assert feed_query._last_feed_query_source == "opensearch"


def test_query_all_records_falls_back_to_ddb_when_opensearch_returns_none(monkeypatch):
    monkeypatch.setattr(feed_query, "_get_active_projects", lambda: [{"project_id": "enceladus"}])
    monkeypatch.setattr(feed_query, "_query_all_records_via_opensearch", lambda _p, _c: None)
    monkeypatch.setattr(
        feed_query,
        "_query_all_records_via_ddb",
        lambda _p, _c: (["t"], [], [], [], []),
    )

    result = feed_query._query_all_records()
    assert result == (["t"], [], [], [], [])
    assert feed_query._last_feed_query_source == "ddb_fanout"


def test_query_all_records_falls_back_to_ddb_when_opensearch_raises(monkeypatch):
    monkeypatch.setattr(feed_query, "_get_active_projects", lambda: [{"project_id": "enceladus"}])

    def _raise(_p, _c):
        raise RuntimeError("boom")

    monkeypatch.setattr(feed_query, "_query_all_records_via_opensearch", _raise)
    monkeypatch.setattr(
        feed_query,
        "_query_all_records_via_ddb",
        lambda _p, _c: ([], [], [], [], []),
    )

    result = feed_query._query_all_records()
    assert result == ([], [], [], [], [])
    assert feed_query._last_feed_query_source == "ddb_fanout"
