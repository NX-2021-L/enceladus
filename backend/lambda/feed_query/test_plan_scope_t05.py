"""ENC-TSK-T05 (ENC-PLN-108 W2.6): GET /api/v1/feed/plan-scope, the Plans page's plan-scoped read.

The property under test is ONE ROW CONTRACT, TWO SCOPES. Rows come from corpus.build_tracker_entries_from_records, the
builder the corpus uses; the scope decides only whether created_at, first_checked_out_at and closed_at are present
(ruling D-26 keeps them off corpus and delta rows). test_corpus.py and test_lambda_function.py assert their ABSENCE
from corpus and delta rows; the tests here assert their PRESENCE at plan scope and re-assert the absence beside them.
"""

from __future__ import annotations

import importlib.util
import json
import os

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "feed_query_lambda_t05",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
feed_query = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(feed_query)

corpus = feed_query.feed_corpus
plan_scope = feed_query.feed_plan_scope

STAMPS = ("created_at", "first_checked_out_at", "closed_at")


# --- pure: plan ordering and the twenty bound --------------------------------------------------------------------------


def _plan(plan_id, created_at=None, **extra):
    row = {"plan_id": plan_id, "project_id": "enceladus", "title": plan_id, "status": "started", "priority": "P2"}
    if created_at is not None:
        row["created_at"] = created_at
    return {**row, **extra}


def test_newest_plans_is_bounded_at_twenty_and_newest_first():
    plans = [_plan(f"ENC-PLN-{n:03d}", f"2026-10-{n:02d}T00:00:00Z") for n in range(1, 26)]
    page = plan_scope.newest_plans(plans)
    assert len(page) == plan_scope.PLAN_PAGE_SIZE == 20
    assert [p["plan_id"] for p in page][:3] == ["ENC-PLN-025", "ENC-PLN-024", "ENC-PLN-023"]
    assert page[-1]["plan_id"] == "ENC-PLN-006"


def test_newest_plans_returns_fewer_when_fewer_exist_and_empty_for_none():
    assert [p["plan_id"] for p in plan_scope.newest_plans([_plan("A-1", "2026-01-01T00:00:00Z")])] == ["A-1"]
    assert plan_scope.newest_plans([]) == []


def test_undated_plans_sort_after_every_dated_plan_and_updated_at_is_not_a_fallback():
    plans = [
        _plan("ENC-PLN-001", None, updated_at="2099-01-01T00:00:00Z"),  # recently touched, no created_at
        _plan("ENC-PLN-002", "2026-01-01T00:00:00Z"),
        _plan("ENC-PLN-003", "not-a-date"),
    ]
    assert [p["plan_id"] for p in plan_scope.newest_plans(plans)] == ["ENC-PLN-002", "ENC-PLN-003", "ENC-PLN-001"]


def test_ties_break_on_plan_id_descending_with_digit_runs_as_numbers():
    same = "2026-05-05T00:00:00Z"
    plans = [_plan("ENC-PLN-9", same), _plan("ENC-PLN-10", same), _plan("ENC-PLN-100", same)]
    assert [p["plan_id"] for p in plan_scope.newest_plans(plans)] == ["ENC-PLN-100", "ENC-PLN-10", "ENC-PLN-9"]


def test_ordering_is_total_so_the_same_input_always_gives_the_same_page():
    plans = [_plan(f"P-{n}", None) for n in (3, 11, 2, 40)]
    assert plan_scope.newest_plans(plans) == plan_scope.newest_plans(list(reversed(plans)))


def test_offset_and_z_forms_of_one_instant_compare_equal_so_the_id_breaks_the_tie():
    plans = [_plan("P-1", "2026-05-05T00:00:00Z"), _plan("P-2", "2026-05-05T00:00:00+00:00")]
    assert [p["plan_id"] for p in plan_scope.newest_plans(plans)] == ["P-2", "P-1"]


# --- pure: the tree walk -----------------------------------------------------------------------------------------------


def _idx(**parents):
    """{task_id: ("enceladus", parent or "")} from kwargs; underscores stand for hyphens to keep call sites terse."""
    return {k.replace("_", "-"): ("enceladus", v.replace("_", "-") if v else "") for k, v in parents.items()}


def test_a_plan_with_no_children_yields_just_its_task_objectives():
    ids, truncated = plan_scope.collect_tree_task_ids([{"objectives_set": ["T-1", "T-2"]}], _idx(T_1="", T_2=""))
    assert ids == ["T-1", "T-2"] and truncated is False


def test_a_plan_with_no_objectives_yields_nothing():
    assert plan_scope.collect_tree_task_ids([{"objectives_set": []}, {}], _idx(T_1="")) == ([], False)


def test_descendants_are_found_by_parent_pointer_in_id_order():
    index = _idx(T_1="", T_1B="T_1", T_1A="T_1", T_9="")
    ids, _ = plan_scope.collect_tree_task_ids([{"objectives_set": ["T-1"]}], index)
    assert ids == ["T-1", "T-1A", "T-1B"]  # T-9 hangs under no objective


def test_deep_tree_stops_at_three_levels_below_the_objective():
    chain = _idx(R="", L1="R", L2="L1", L3="L2", L4="L3", L5="L4")
    ids, truncated = plan_scope.collect_tree_task_ids([{"objectives_set": ["R"]}], chain)
    assert ids == ["R", "L1", "L2", "L3"]
    assert "L4" not in ids and plan_scope.MAX_DESCENDANT_DEPTH == 3
    assert truncated is False  # the depth bound is a design limit, not truncation


def test_a_root_below_another_root_is_expanded_to_its_own_depth():
    # A -> B -> B1 -> B2 -> B3 ; B is also an objective. From A the walk reaches B3 at depth 4 and stops, but B's own
    # walk is rooted at B, so B3 is reached at depth 3 and must be present.
    index = _idx(A="", B="A", B1="B", B2="B1", B3="B2")
    ids, _ = plan_scope.collect_tree_task_ids([{"objectives_set": ["A", "B"]}], index)
    assert set(ids) == {"A", "B", "B1", "B2", "B3"}


def test_non_task_objectives_and_non_task_descendants_are_not_tree_members():
    # task_parents holds TASKS only. ISS-1 (an issue objective) and ENC-FTR-1 are not in it; an issue whose parent is a
    # task is not in it either, so none of them is walked or returned.
    index = _idx(T_1="", T_2="T_1")
    ids, _ = plan_scope.collect_tree_task_ids([{"objectives_set": ["ENC-ISS-1", "T-1", "ENC-FTR-1", "MISSING"]}], index)
    assert ids == ["T-1", "T-2"]


def test_parent_cycle_terminates():
    index = _idx(A="B", B="A", C="C")
    ids, _ = plan_scope.collect_tree_task_ids([{"objectives_set": ["A", "C"]}], index)
    assert sorted(ids) == ["A", "B", "C"]


def test_tasks_shared_by_two_plans_are_returned_once():
    index = _idx(T_1="", T_2="T_1")
    ids, _ = plan_scope.collect_tree_task_ids([{"objectives_set": ["T-1"]}, {"objectives_set": ["T-1"]}], index)
    assert ids == ["T-1", "T-2"]


def test_task_ceiling_truncates_and_says_so():
    index = _idx(R="", **{f"K{n:02d}": "R" for n in range(10)})
    ids, truncated = plan_scope.collect_tree_task_ids([{"objectives_set": ["R"]}], index, max_tasks=4)
    assert len(ids) == 4 and truncated is True
    ids, truncated = plan_scope.collect_tree_task_ids([{"objectives_set": ["R"]}], index, max_tasks=11)
    assert len(ids) == 11 and truncated is False


def test_subtask_ids_is_never_read():
    # The lens refuses subtask_ids (fixture F5: it disagrees with parent). A plan record carrying it changes nothing.
    index = _idx(T_1="", T_2="")
    ids, _ = plan_scope.collect_tree_task_ids([{"objectives_set": ["T-1"], "subtask_ids": ["T-2"]}], index)
    assert ids == ["T-1"]


# --- lens_attrs: one helper, two scopes --------------------------------------------------------------------------------

_STAMPED = {
    "created_at": "2026-01-01T00:00:00Z",
    "first_checked_out_at": "2026-01-02T00:00:00Z",
    "closed_at": "2026-01-03T00:00:00Z",
}


def test_corpus_scope_is_the_default_and_never_emits_a_timestamp():
    record = {"parent": "P", "wave": "W1", "objectives_set": ["A"], **_STAMPED}
    for record_type in ("task", "plan", "issue", "feature", "lesson"):
        assert corpus.lens_attrs(record_type, "X-1", record) == corpus.lens_attrs(
            record_type, "X-1", record, corpus.LENS_SCOPE_CORPUS
        )
        assert not set(STAMPS) & set(corpus.lens_attrs(record_type, "X-1", record))


def test_plan_scope_adds_exactly_the_three_timestamps_to_task_and_plan_rows():
    task = corpus.lens_attrs("task", "T-1", {"parent": "P", "wave": "W2.1", **_STAMPED}, corpus.LENS_SCOPE_PLAN)
    assert task == {"parent": "P", "wave": "W2.1", **_STAMPED}
    plan = corpus.lens_attrs("plan", "PLN-1", {"objectives_set": ["T-1"], **_STAMPED}, corpus.LENS_SCOPE_PLAN)
    assert plan == {"objectives_set": ["T-1"], **_STAMPED}


def test_plan_scope_omits_each_timestamp_when_empty_and_never_invents_one():
    out = corpus.lens_attrs("task", "T-1", {"created_at": "2026-01-01T00:00:00Z", "closed_at": "  ", "first_checked_out_at": None}, "plan")
    assert out == {"created_at": "2026-01-01T00:00:00Z"}
    assert corpus.lens_attrs("task", "T-1", {}, "plan") == {}


def test_plan_scope_adds_nothing_to_types_the_lens_does_not_read():
    for record_type in ("issue", "feature", "lesson"):
        assert corpus.lens_attrs(record_type, "X-1", dict(_STAMPED), "plan") == {}


def test_an_unknown_scope_is_refused_rather_than_silently_widened():
    with pytest.raises(ValueError):
        corpus.lens_attrs("task", "T-1", dict(_STAMPED), "everything")
    with pytest.raises(ValueError):
        corpus.build_tracker_entries_from_records([], [], [], [], [], lens_scope="everything")


def test_same_record_one_row_shape_in_both_scopes():
    task = {"task_id": "ENC-TSK-1", "project_id": "enceladus", "title": "t", "status": "open", "priority": "P1",
            "category": "implementation", "updated_at": "2026-11-19T00:00:00Z", "version_seq": 7,
            "parent": "ENC-TSK-0", "wave": "W2.6", **_STAMPED}
    plan = {"plan_id": "ENC-PLN-1", "project_id": "enceladus", "title": "p", "status": "started", "priority": "P1",
            "updated_at": "2026-11-19T00:00:00Z", "objectives_set": ["ENC-TSK-1"], **_STAMPED}
    in_corpus = corpus.build_tracker_entries_from_records([task], [], [], [], [plan])
    in_plan = corpus.build_tracker_entries_from_records([task], [], [], [], [plan], lens_scope=corpus.LENS_SCOPE_PLAN)
    assert len(in_corpus) == len(in_plan) == 2
    for a, b in zip(in_corpus, in_plan):
        assert list(a) == list(b)  # same top-level keys in the same order: the same row
        assert {k: v for k, v in b.items() if k != "attrs"} == {k: v for k, v in a.items() if k != "attrs"}
        assert {k: v for k, v in b["attrs"].items() if k not in STAMPS} == a["attrs"]  # plan = corpus + three
        assert not set(STAMPS) & set(a["attrs"])
        assert {"created_at", "closed_at", "first_checked_out_at"} >= set(b["attrs"]) & set(STAMPS)
    assert {k: in_plan[0]["attrs"][k] for k in STAMPS} == _STAMPED
    assert in_plan[0]["attrs"]["parent"] == "ENC-TSK-0" and in_plan[0]["attrs"]["wave"] == "W2.6"
    assert in_plan[1]["attrs"]["objectives_set"] == ["ENC-TSK-1"]


def test_the_shared_task_transform_still_does_not_carry_the_stamps():
    # The plan scope reads first_checked_out_at / closed_at from the raw item through an overlay precisely so that
    # _transform_task_from_ddb, which also feeds GET /api/v1/feed and /feed/tasks.json, does not change by a byte.
    raw = _task_item("ENC-TSK-1", first_checked_out_at="2026-01-02T00:00:00Z", closed_at="2026-01-03T00:00:00Z")
    out = feed_query._transform_task_from_ddb(raw, "enceladus")
    assert "first_checked_out_at" not in out and "closed_at" not in out


# --- the route, end to end through a fake DynamoDB ---------------------------------------------------------------------


def _s(v):
    return {"S": v}


def _task_item(task_id, project="enceladus", **extra):
    item = {
        "project_id": _s(project), "record_id": _s(f"task#{task_id}"), "record_type": _s("task"), "item_id": _s(task_id),
        "title": _s(f"title {task_id}"), "status": _s("open"), "priority": _s("P2"), "updated_at": _s("2026-11-19T00:00:00Z"),
        "created_at": _s("2026-11-01T00:00:00Z"),
    }
    for key, value in extra.items():
        item[key] = _s(value) if isinstance(value, str) else value
    return item


def _plan_item(plan_id, created_at, objectives=(), project="enceladus", **extra):
    item = {
        "project_id": _s(project), "record_id": _s(f"plan#{plan_id}"), "record_type": _s("plan"), "item_id": _s(plan_id),
        "title": _s(f"plan {plan_id}"), "status": _s("started"), "priority": _s("P2"), "updated_at": _s("2026-11-19T00:00:00Z"),
    }
    if created_at:
        item["created_at"] = _s(created_at)
    if objectives:
        item["objectives_set"] = {"L": [_s(o) for o in objectives]}
    for key, value in extra.items():
        item[key] = _s(value) if isinstance(value, str) else value
    return item


def _issue_item(issue_id, parent, project="enceladus"):
    return {
        "project_id": _s(project), "record_id": _s(f"issue#{issue_id}"), "record_type": _s("issue"), "item_id": _s(issue_id),
        "title": _s("an issue"), "status": _s("open"), "priority": _s("P2"), "parent": _s(parent),
        "updated_at": _s("2026-11-19T00:00:00Z"), "created_at": _s("2026-11-02T00:00:00Z"),
    }


class _Pager:
    def __init__(self, items):
        self._items = items

    def paginate(self, **kwargs):
        values = kwargs.get("ExpressionAttributeValues", {})
        pid = values[":pid"]["S"]
        rtype = values.get(":rt", {}).get("S")
        rows = [i for i in self._items if i["project_id"]["S"] == pid and (rtype is None or i["record_type"]["S"] == rtype)]
        yield {"Items": rows[:60]}
        yield {"Items": rows[60:]}


class _FakeDDB:
    def __init__(self, items):
        self.items = items
        self.paginations = 0
        self.batch_get_keys = []

    def get_paginator(self, name):
        assert name == "query"
        self.paginations += 1
        return _Pager(self.items)

    def batch_get_item(self, RequestItems):
        (table, spec), = RequestItems.items()
        by_key = {(i["project_id"]["S"], i["record_id"]["S"]): i for i in self.items}
        got = []
        for key in spec["Keys"]:
            self.batch_get_keys.append(key["record_id"]["S"])
            hit = by_key.get((key["project_id"]["S"], key["record_id"]["S"]))
            if hit:
                got.append(hit)
        return {"Responses": {table: got}, "UnprocessedKeys": {}}

    def scan(self, **_kwargs):
        return {"Items": []}


@pytest.fixture
def world(monkeypatch):
    """Install a fake tracker. Returns a function that loads items; caches are reset for every test."""

    def load(items, projects=("enceladus",)):
        fake = _FakeDDB(items)
        monkeypatch.setattr(feed_query, "_get_ddb", lambda: fake)
        monkeypatch.setattr(feed_query, "_get_active_projects", lambda: [{"project_id": p} for p in projects])
        monkeypatch.setattr(feed_query, "_corpus_cache_entries", None)
        monkeypatch.setattr(feed_query, "_corpus_cache_at", 0.0)
        monkeypatch.setattr(feed_query, "_document_cache_items", None)
        monkeypatch.setattr(feed_query, "_task_parent_cache", None)
        monkeypatch.setattr(feed_query, "_task_parent_cache_at", 0.0)
        return fake

    return load


def _call(path="/api/v1/feed/plan-scope", query=None, authed=True):
    event = {
        "requestContext": {"http": {"method": "GET"}},
        "rawPath": path,
        "headers": {"Cookie": "enceladus_id_token=test-token"} if authed else {},
        "queryStringParameters": query or {},
    }
    return feed_query.lambda_handler(event, None)


def _body(resp):
    assert resp["statusCode"] == 200, resp
    return json.loads(resp["body"])


@pytest.fixture(autouse=True)
def _auth(monkeypatch):
    monkeypatch.setattr(feed_query, "_verify_token", lambda _t: {"sub": "u-1"})


def _tree_world():
    """PLN-2 (newest) has a three-level tree and a non-task objective; PLN-1 has no children; PLN-0 is undated."""
    return [
        _plan_item("ENC-PLN-001", "2026-10-01T00:00:00Z", ["ENC-TSK-A"]),
        _plan_item("ENC-PLN-002", "2026-11-01T00:00:00Z", ["ENC-TSK-B", "ENC-ISS-9", "ENC-TSK-NOPE"]),
        _plan_item("ENC-PLN-000", None, []),
        _task_item("ENC-TSK-A", first_checked_out_at="2026-10-02T00:00:00Z", closed_at="2026-10-03T00:00:00Z"),
        _task_item("ENC-TSK-B", wave="W1", first_checked_out_at="2026-11-02T00:00:00Z"),
        _task_item("ENC-TSK-B1", parent="ENC-TSK-B", created_at="2026-11-03T00:00:00Z"),
        _task_item("ENC-TSK-B2", parent="ENC-TSK-B1", closed_at="2026-11-04T00:00:00Z", first_checked_out_at="2026-11-03T12:00:00Z"),
        _task_item("ENC-TSK-B3", parent="ENC-TSK-B2"),
        _task_item("ENC-TSK-B4", parent="ENC-TSK-B3"),  # depth 4 below B: outside the bound
        _task_item("ENC-TSK-ELSE"),  # in no plan's tree
        _issue_item("ENC-ISS-9", parent="ENC-TSK-B"),  # a non-task descendant and a non-task objective
    ]


def test_route_requires_the_same_auth_as_the_corpus(world):
    world(_tree_world())
    resp = _call(authed=False)
    assert resp["statusCode"] == 401
    assert _call("/api/v1/feed/corpus", authed=False)["statusCode"] == 401


def test_route_returns_plans_newest_first_then_the_task_rows_of_their_trees(world):
    world(_tree_world())
    body = _body(_call())
    assert body["scope"] == "plan" and body["page_size"] == 20 and body["truncated"] is False
    plans = [r["record_id"] for r in body["items"] if r["record_type"] == "plan"]
    tasks = [r["record_id"] for r in body["items"] if r["record_type"] == "task"]
    assert plans == ["ENC-PLN-002", "ENC-PLN-001", "ENC-PLN-000"]
    assert tasks == ["ENC-TSK-A", "ENC-TSK-B", "ENC-TSK-B1", "ENC-TSK-B2", "ENC-TSK-B3"]
    assert [r["record_type"] for r in body["items"]] == ["plan"] * 3 + ["task"] * 5  # plans first, then tasks
    assert (body["total_plans"], body["plan_count"], body["task_count"]) == (3, 3, 5)


def test_route_never_includes_non_task_descendants_or_tasks_outside_the_trees_or_beyond_depth_three(world):
    world(_tree_world())
    ids = {r["record_id"] for r in _body(_call())["items"]}
    assert "ENC-ISS-9" not in ids  # an issue, whether objective or descendant
    assert "ENC-TSK-ELSE" not in ids  # in no plan's tree
    assert "ENC-TSK-B4" not in ids  # four levels below the objective
    assert "ENC-TSK-NOPE" not in ids  # objective with no record


def test_task_rows_carry_the_three_lifecycle_timestamps_and_parent_and_wave(world):
    world(_tree_world())
    rows = {r["record_id"]: r for r in _body(_call())["items"]}
    b2 = rows["ENC-TSK-B2"]["attrs"]
    assert b2["created_at"] == "2026-11-01T00:00:00Z"
    assert b2["first_checked_out_at"] == "2026-11-03T12:00:00Z"
    assert b2["closed_at"] == "2026-11-04T00:00:00Z"
    assert b2["parent"] == "ENC-TSK-B1"
    assert rows["ENC-TSK-B"]["attrs"]["wave"] == "W1"
    # A timestamp the record does not carry is omitted, never null.
    assert "closed_at" not in rows["ENC-TSK-B"]["attrs"] and "first_checked_out_at" not in rows["ENC-TSK-B3"]["attrs"]
    assert all(v for r in rows.values() for k, v in r["attrs"].items() if k in STAMPS)
    # AC-3: created_at on the task rows of the tree, from the record's own created_at.
    assert rows["ENC-TSK-B1"]["attrs"]["created_at"] == "2026-11-03T00:00:00Z"


def test_plan_rows_carry_objectives_set_in_stored_order_and_created_at(world):
    world(_tree_world())
    rows = {r["record_id"]: r for r in _body(_call())["items"]}
    assert rows["ENC-PLN-002"]["attrs"]["objectives_set"] == ["ENC-TSK-B", "ENC-ISS-9", "ENC-TSK-NOPE"]
    assert rows["ENC-PLN-002"]["attrs"]["created_at"] == "2026-11-01T00:00:00Z"
    assert "created_at" not in rows["ENC-PLN-000"]["attrs"]  # undated: omitted, and it sorts last
    assert "objectives_set" not in rows["ENC-PLN-000"]["attrs"]  # a plan with no children and no objectives


def test_route_rows_have_the_corpus_row_shape(world):
    """The same record through /feed/corpus and /feed/plan-scope: same row, corpus attrs plus the three timestamps."""
    world(_tree_world())
    corpus_rows = {r["record_id"]: r for r in feed_query._get_corpus_entries() if r["source"] == "tracker"}
    plan_rows = {r["record_id"]: r for r in _body(_call())["items"]}
    assert plan_rows and set(plan_rows) <= set(corpus_rows)
    for record_id, row in plan_rows.items():
        twin = corpus_rows[record_id]
        assert list(row) == list(twin), record_id
        assert {k: v for k, v in row.items() if k != "attrs"} == {k: v for k, v in twin.items() if k != "attrs"}
        assert {k: v for k, v in row["attrs"].items() if k not in STAMPS} == twin["attrs"], record_id
        assert not set(STAMPS) & set(twin["attrs"]), record_id  # D-26: never on the corpus row


def test_corpus_and_delta_scopes_still_omit_the_timestamps_next_to_this_route(world):
    world(_tree_world())
    page = _body(_call("/api/v1/feed/corpus", {"limit": "200"}))
    tracker = [r for r in page["items"] if r["source"] == "tracker"]
    assert tracker
    for row in tracker:
        assert not set(STAMPS) & set(row["attrs"]), row["record_id"]
        assert not set(STAMPS) & set(row), row["record_id"]
    delta_row = feed_query._delta_corpus_entry(
        _task_item("ENC-TSK-B2", parent="ENC-TSK-B1", closed_at="2026-11-04T00:00:00Z", first_checked_out_at="2026-11-03T12:00:00Z"),
        "enceladus",
    )
    assert not set(STAMPS) & set(delta_row["attrs"]) and delta_row["attrs"]["parent"] == "ENC-TSK-B1"


def test_twenty_is_the_bound_and_fewer_is_fine(world):
    items = [_plan_item(f"ENC-PLN-{n:03d}", f"2026-09-{n:02d}T00:00:00Z", [f"ENC-TSK-{n}"]) for n in range(1, 26)]
    items += [_task_item(f"ENC-TSK-{n}") for n in range(1, 26)]
    world(items)
    body = _body(_call())
    plans = [r["record_id"] for r in body["items"] if r["record_type"] == "plan"]
    assert len(plans) == 20 and plans[0] == "ENC-PLN-025" and plans[-1] == "ENC-PLN-006"
    assert body["total_plans"] == 25
    tasks = [r["record_id"] for r in body["items"] if r["record_type"] == "task"]
    assert len(tasks) == 20  # only the trees of the twenty shown: the five oldest plans' tasks are not fetched

    world([_plan_item("ENC-PLN-001", "2026-09-01T00:00:00Z")])
    assert _body(_call())["plan_count"] == 1


def test_a_task_hanging_under_the_newest_plan_is_found_by_a_batch_get_of_task_keys_only(world):
    fake = world(_tree_world())
    _call()
    assert fake.batch_get_keys and all(k.startswith("task#") for k in fake.batch_get_keys)
    assert "task#ENC-TSK-ELSE" not in fake.batch_get_keys and "task#ENC-TSK-B4" not in fake.batch_get_keys


def test_project_filter_matches_the_corpus_query_parameter(world):
    items = [
        _plan_item("ENC-PLN-001", "2026-10-01T00:00:00Z", ["ENC-TSK-1"]),
        _task_item("ENC-TSK-1"),
        _plan_item("HFY-PLN-001", "2026-11-01T00:00:00Z", ["HFY-TSK-1"], project="harrisonfamily"),
        _task_item("HFY-TSK-1", project="harrisonfamily"),
    ]
    world(items, projects=("enceladus", "harrisonfamily"))
    both = _body(_call())
    assert [r["record_id"] for r in both["items"] if r["record_type"] == "plan"] == ["HFY-PLN-001", "ENC-PLN-001"]
    only = _body(_call(query={"project_id": "HarrisonFamily"}))
    assert [r["record_id"] for r in only["items"]] == ["HFY-PLN-001", "HFY-TSK-1"]
    assert {r["project_id"] for r in only["items"]} == {"harrisonfamily"}


def test_response_headers_match_corpus_and_delta(world):
    world(_tree_world())
    resp = _call()
    assert resp["headers"]["Cache-Control"] == "no-cache, no-store, must-revalidate"
    assert resp["headers"]["Content-Type"] == "application/json"


def test_a_corpus_failure_is_a_500_not_a_stack_trace(world, monkeypatch):
    world(_tree_world())
    monkeypatch.setattr(feed_query, "_get_task_parent_index", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    resp = _call()
    assert resp["statusCode"] == 500 and "boom" not in resp["body"]


def test_warm_corpus_cache_supplies_the_parent_map_without_a_tracker_load(world, monkeypatch):
    fake = world(_tree_world())
    feed_query._get_corpus_entries()  # warms the corpus cache
    paginations_before = fake.paginations

    def boom():
        raise AssertionError("must not reload the tracker when the corpus cache is warm")

    monkeypatch.setattr(feed_query, "_query_corpus_tracker_records", boom)
    monkeypatch.setattr(feed_query, "_corpus_cache_at", feed_query.time.time())
    index = feed_query._get_task_parent_index()
    assert index["ENC-TSK-B2"] == ("enceladus", "ENC-TSK-B1") and index["ENC-TSK-A"] == ("enceladus", "")
    assert fake.paginations == paginations_before
    assert "ENC-ISS-9" not in index  # tasks only
