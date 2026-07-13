"""Tests for tracker_list's ENC-ISS-558 lower-bound contract.

The raw tracker API has no page-independent 'total' field -- only 'count'
(this page) and 'next_cursor' (more data outstanding or not). These tests
verify _tracker_list():
  - forwards page_size/cursor to the raw request (the actual root cause of
    the ~8x undercount -- previously never forwarded at all)
  - marks 'total' with total_is_lower_bound=true whenever a next_cursor
    remains outstanding, rather than presenting a page-scoped count as a
    full-project total
  - supports an opt-in exhaust=true bounded-exhaustion mode with an exact
    total, or exhaustion_truncated=true if the page guard is hit first

Related: ENC-ISS-558, ENC-ISS-557 (sibling fix, same pattern in sense.py)
"""

import asyncio
import importlib.util
import json
import pathlib
import sys
from unittest.mock import patch

MODULE_PATH = pathlib.Path(__file__).with_name("server.py")
SPEC = importlib.util.spec_from_file_location("enceladus_server_tracker_list", MODULE_PATH)
server = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = server
SPEC.loader.exec_module(server)


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _call_tracker_list(args: dict) -> dict:
    content = _run(server._tracker_list(args))
    assert content, "tracker_list returned empty content"
    return json.loads(content[0].text)


def _task(i: int) -> dict:
    return {
        "id": f"ENC-TSK-{i}",
        "record_type": "task",
        "status": "open",
        "priority": "P2",
        "title": f"task {i}",
        "parent": "ENC-TSK-0",
    }


def test_no_next_cursor_reports_exact_total():
    """Single raw page, nothing outstanding -> total is exact, no lower-bound flag."""
    page = [_task(i) for i in range(24)]

    def fake_request(method, path, payload=None, query=None):
        assert query["page_size"] == 25
        assert "next_cursor" not in query
        return {"records": page, "count": len(page)}

    with patch.object(server, "_tracker_api_request", side_effect=fake_request):
        result = _call_tracker_list({"project_id": "enceladus", "record_type": "task", "status": "open"})

    assert result["total"] == 24
    assert result["count"] == 24
    assert "total_is_lower_bound" not in result
    assert "next_cursor" not in result


def test_outstanding_cursor_marks_total_as_lower_bound():
    """This is the ENC-ISS-558 bug: raw API returns a full page AND a next_cursor,
    meaning far more records exist than this one page. 'total' must never be
    reported as an exact full-project count in this case."""
    page = [_task(i) for i in range(200)]

    def fake_request(method, path, payload=None, query=None):
        return {"records": page, "count": len(page), "next_cursor": "opaque-cursor-1"}

    with patch.object(server, "_tracker_api_request", side_effect=fake_request):
        result = _call_tracker_list(
            {"project_id": "enceladus", "record_type": "task", "status": "open", "page_size": 200}
        )

    assert result["total"] == 200
    assert result["total_is_lower_bound"] is True
    assert result["next_cursor"] == "opaque-cursor-1"


def test_page_size_and_cursor_are_forwarded_to_raw_request():
    """Root-cause regression guard: previously page_size/cursor were never
    forwarded to the raw API at all, so a caller's cursor never advanced the
    underlying query -- every call re-fetched the same default page."""
    captured = []

    def fake_request(method, path, payload=None, query=None):
        captured.append(dict(query))
        return {"records": [], "count": 0}

    with patch.object(server, "_tracker_api_request", side_effect=fake_request):
        _call_tracker_list(
            {
                "project_id": "enceladus",
                "record_type": "task",
                "status": "open",
                "page_size": 50,
                "cursor": "prior-cursor-token",
            }
        )

    assert len(captured) == 1
    assert captured[0]["page_size"] == 50
    assert captured[0]["next_cursor"] == "prior-cursor-token"
    assert captured[0]["type"] == "task"
    assert captured[0]["status"] == "open"


def test_exhaust_walks_to_true_exact_total():
    """exhaust=true walks next_cursor until the raw API naturally exhausts it,
    producing an exact total with no lower-bound flag."""
    pages = [
        {"records": [_task(i) for i in range(200)], "count": 200, "next_cursor": "cursor-2"},
        {"records": [_task(i) for i in range(200, 400)], "count": 200, "next_cursor": "cursor-3"},
        {"records": [_task(i) for i in range(400, 437)], "count": 37},
    ]
    calls = {"n": 0}

    def fake_request(method, path, payload=None, query=None):
        resp = pages[calls["n"]]
        calls["n"] += 1
        return resp

    with patch.object(server, "_tracker_api_request", side_effect=fake_request):
        result = _call_tracker_list(
            {"project_id": "enceladus", "record_type": "task", "status": "open", "page_size": 200, "exhaust": True}
        )

    assert calls["n"] == 3
    assert result["total"] == 437
    assert "total_is_lower_bound" not in result
    assert "exhaustion_truncated" not in result
    assert "next_cursor" not in result


def test_exhaust_hits_page_guard_and_marks_truncated():
    """exhaust=true must never loop unbounded against the raw API -- if the
    _TRACKER_LIST_MAX_EXHAUST_PAGES guard trips before the cursor naturally
    empties, the result is still an honest lower bound, not a silent total."""
    call_count = {"n": 0}

    def fake_request(method, path, payload=None, query=None):
        call_count["n"] += 1
        return {"records": [_task(call_count["n"])], "count": 1, "next_cursor": f"cursor-{call_count['n']}"}

    with patch.object(server, "_tracker_api_request", side_effect=fake_request):
        result = _call_tracker_list(
            {"project_id": "enceladus", "record_type": "task", "status": "open", "exhaust": True}
        )

    assert call_count["n"] == server._TRACKER_LIST_MAX_EXHAUST_PAGES
    assert result["total_is_lower_bound"] is True
    assert result["exhaustion_truncated"] is True
    assert result["next_cursor"]


def test_orphan_count_also_marked_as_lower_bound_when_capped():
    page = [_task(i) for i in range(5)]
    page[0].pop("parent")  # one orphan in this page

    def fake_request(method, path, payload=None, query=None):
        return {"records": page, "count": len(page), "next_cursor": "more-out-there"}

    with patch.object(server, "_tracker_api_request", side_effect=fake_request):
        result = _call_tracker_list({"project_id": "enceladus", "record_type": "task", "status": "open"})

    assert result["orphan_tasks"] == 1
    assert result["orphan_tasks_is_lower_bound"] is True


if __name__ == "__main__":
    failures = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  PASS {name}")
            except AssertionError as exc:
                failures += 1
                print(f"  FAIL {name}: {exc}")
    if failures:
        print(f"\n{failures} test(s) FAILED")
        sys.exit(1)
    print("\nAll tests passed!")
