"""Unit tests for the server-side feed page cap + cursor continuation (ENC-TSK-M74)."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import feed_page  # noqa: E402
from corpus import decode_cursor  # noqa: E402


def _rec(id_key: str, rid: str, updated_at: str, project_id: str = "enceladus") -> dict:
    return {id_key: rid, "project_id": project_id, "updated_at": updated_at, "title": rid}


def _tasks(n: int, *, base_ts: str = "2026-07-10T") -> list:
    # Descending timestamps so record order is unambiguous: T00 newest .. Tnn oldest.
    return [_rec("task_id", f"ENC-TSK-{i:03d}", f"{base_ts}{(59 - i) % 60:02d}:00:00Z") for i in range(n)]


def _all(tasks=None, issues=None, features=None, lessons=None, plans=None):
    return (tasks or [], issues or [], features or [], lessons or [], plans or [])


def _count(*arrays) -> int:
    return sum(len(a) for a in arrays)


def test_below_cap_returns_everything_and_null_cursor():
    tasks = _tasks(10)
    t, i, f, l, p, cur = feed_page.apply_page_cap(*_all(tasks=tasks), cap=75)
    assert _count(t, i, f, l, p) == 10
    assert cur is None


def test_exactly_at_cap_returns_null_cursor():
    tasks = _tasks(75)
    t, i, f, l, p, cur = feed_page.apply_page_cap(*_all(tasks=tasks), cap=75)
    assert _count(t, i, f, l, p) == 75
    assert cur is None


def test_over_cap_truncates_and_emits_cursor():
    tasks = _tasks(76)
    t, i, f, l, p, cur = feed_page.apply_page_cap(*_all(tasks=tasks), cap=75)
    assert _count(t, i, f, l, p) == 75
    assert cur is not None
    assert decode_cursor(cur) is not None


def test_cap_is_global_across_typed_arrays():
    # 50 tasks + 50 issues -> 100 records, cap 75 keeps 75 total across arrays.
    tasks = [_rec("task_id", f"ENC-TSK-{i:03d}", f"2026-07-10T{i:02d}:00:00Z") for i in range(50)]
    issues = [_rec("issue_id", f"ENC-ISS-{i:03d}", f"2026-07-09T{i:02d}:00:00Z") for i in range(50)]
    t, i, f, l, p, cur = feed_page.apply_page_cap(*_all(tasks=tasks, issues=issues), cap=75)
    assert _count(t, i, f, l, p) == 75
    assert cur is not None


def test_ordering_is_recency_desc_with_record_key_tiebreak():
    # Two records share a timestamp; record_key (tracker:project:id) breaks the tie ASC.
    tasks = [
        _rec("task_id", "ENC-TSK-BBB", "2026-07-10T09:00:00Z"),
        _rec("task_id", "ENC-TSK-AAA", "2026-07-10T09:00:00Z"),
        _rec("task_id", "ENC-TSK-CCC", "2026-07-10T12:00:00Z"),
    ]
    t, *_ = feed_page.apply_page_cap(*_all(tasks=tasks), cap=75)
    ids = [r["task_id"] for r in t]
    assert ids == ["ENC-TSK-CCC", "ENC-TSK-AAA", "ENC-TSK-BBB"]


def test_ordering_is_deterministic_across_input_permutations():
    import random

    tasks = _tasks(40)
    shuffled = tasks[:]
    random.Random(7).shuffle(shuffled)
    a = feed_page.apply_page_cap(*_all(tasks=tasks), cap=75)[0]
    b = feed_page.apply_page_cap(*_all(tasks=shuffled), cap=75)[0]
    assert [r["task_id"] for r in a] == [r["task_id"] for r in b]


def test_empty_updated_at_sorts_last():
    tasks = [
        _rec("task_id", "ENC-TSK-NEW", "2026-07-10T10:00:00Z"),
        {"task_id": "ENC-TSK-NOTS", "project_id": "enceladus", "title": "x"},  # no updated_at
    ]
    t, *_ = feed_page.apply_page_cap(*_all(tasks=tasks), cap=1)
    assert [r["task_id"] for r in t] == ["ENC-TSK-NEW"]


def test_cursor_continuation_no_overlap_no_gap_full_traversal():
    tasks = _tasks(160)
    seen = []
    cursor = None
    pages = 0
    while True:
        t, i, f, l, p, cursor = feed_page.apply_page_cap(
            *_all(tasks=tasks), cursor=cursor, cap=75
        )
        pages += 1
        seen.extend(r["task_id"] for r in (t + i + f + l + p))
        if cursor is None:
            break
        assert pages < 10  # guard against infinite loop
    # Full traversal reconstructs the full set exactly once, in stable order.
    assert len(seen) == 160
    assert len(set(seen)) == 160
    single = feed_page.apply_page_cap(*_all(tasks=tasks), cap=0)[0]
    assert seen == [r["task_id"] for r in single]


def test_per_record_output_is_byte_identical():
    # The record dicts returned must be the very same objects, unmutated.
    tasks = _tasks(3)
    before = [dict(r) for r in tasks]
    t, *_ = feed_page.apply_page_cap(*_all(tasks=tasks), cap=75)
    for original, returned in zip(before, sorted(t, key=lambda r: r["task_id"])):
        assert returned == original


def test_invalid_cursor_falls_back_to_top_defensively():
    tasks = _tasks(10)
    t, *_rest, cur = feed_page.apply_page_cap(*_all(tasks=tasks), cursor="!!!not-base64!!!", cap=75)
    # Undecodable cursor -> start from top (handler 400s before this in practice).
    assert len(t) == 10
    assert cur is None
