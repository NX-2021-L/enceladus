"""Tests for tracker_list's ENC-ISS-558 lower-bound contract.

The raw tracker API has no page-independent 'total' field -- only 'count'
(this page) and 'next_cursor' (more data outstanding or not). These tests
verify _tracker_list():
  - forwards page_size/cursor to the raw request (the actual root cause of
    the ~8x undercount -- previously never forwarded at all)
  - marks 'total' with total_is_lower_bound=true whenever a next_cursor
    remains outstanding, rather than presenting a page-scoped count as a
    full-project total
  - supports an opt-in exhaust=true mode that gets its total from a
    server-side census (ENC-TSK-Q15, O3.3), with exhaustion_truncated=true
    if the census itself reports count_truncated
  - forwards mode=census verbatim, bypassing the records/total reshaping
    entirely (ENC-TSK-Q15, O3.1)

Related: ENC-ISS-558, ENC-ISS-557 (sibling fix, same pattern in sense.py),
ENC-TSK-Q15 (census pass-through + census-backed exhaust)
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


def test_exhaust_uses_census():
    """ENC-TSK-Q15 (O3.3): exhaust=true is re-implemented over the server-side
    census instead of a bounded raw-page walk. A raw-route fake that omits the
    cursor (i.e. would previously have looked page-exhausted) with rows still
    remaining must never leak the short page count as 'total' -- the true
    count comes from the census fake, even when the two disagree."""
    calls = []

    def fake_request(method, path, payload=None, query=None):
        calls.append(dict(query))
        if query.get("mode") == "census":
            return {"count": 437, "count_truncated": False, "pages": []}
        # Raw route page omits next_cursor even though far more rows remain --
        # exhaust must not mistake this short page for the real total.
        return {"records": [_task(i) for i in range(5)], "count": 5}

    with patch.object(server, "_tracker_api_request", side_effect=fake_request):
        result = _call_tracker_list(
            {"project_id": "enceladus", "record_type": "task", "status": "open", "page_size": 200, "exhaust": True}
        )

    assert len(calls) == 2
    assert calls[0]["mode"] == "census"
    assert "mode" not in calls[1]
    assert result["total"] == 437
    assert "total_is_lower_bound" not in result
    assert "exhaustion_truncated" not in result
    assert result["count"] == 5
    assert len(result["records"]) == 5


def test_exhaust_marks_truncated_from_census():
    """When the census itself reports count_truncated, exhaust must surface
    that honestly (total_is_lower_bound + exhaustion_truncated) rather than
    claiming an exact total."""
    def fake_request(method, path, payload=None, query=None):
        if query.get("mode") == "census":
            return {"count": 1000, "count_truncated": True, "pages": []}
        return {"records": [_task(i) for i in range(25)], "count": 25, "next_cursor": "more"}

    with patch.object(server, "_tracker_api_request", side_effect=fake_request):
        result = _call_tracker_list(
            {"project_id": "enceladus", "record_type": "task", "status": "open", "exhaust": True}
        )

    assert result["total"] == 1000
    assert result["total_is_lower_bound"] is True
    assert result["exhaustion_truncated"] is True
    assert result["next_cursor"] == "more"


def test_orphan_count_also_marked_as_lower_bound_when_capped():
    page = [_task(i) for i in range(5)]
    page[0].pop("parent")  # one orphan in this page

    def fake_request(method, path, payload=None, query=None):
        return {"records": page, "count": len(page), "next_cursor": "more-out-there"}

    with patch.object(server, "_tracker_api_request", side_effect=fake_request):
        result = _call_tracker_list({"project_id": "enceladus", "record_type": "task", "status": "open"})

    assert result["orphan_tasks"] == 1
    assert result["orphan_tasks_is_lower_bound"] is True


def test_exhaust_orphan_tasks_is_lower_bound_when_page_one_is_partial():
    """Review-fix regression (ENC-TSK-Q15-0C): under exhaust=true, orphan_tasks
    is always computed from only first_page_items (page 1), never a full
    project walk. If the census total happens to be EXACT (count_truncated=
    False) while page 1's own fetch still leaves a next_cursor outstanding,
    'total' correctly carries no lower-bound flag (the census covered the
    whole project) but 'orphan_tasks' must still be marked as a lower bound,
    because only page 1's rows were ever scanned for orphan status. Failing
    to do so would silently under-report the orphan count as if exact."""
    page = [_task(i) for i in range(5)]
    page[0].pop("parent")  # one orphan visible on page 1

    def fake_request(method, path, payload=None, query=None):
        if query.get("mode") == "census":
            # Exact census total: the WHOLE project was walked and counted,
            # so count_truncated=False -- but that says nothing about
            # whether page 1 alone (fetched separately below) covers every
            # row, since page_size can be far smaller than the project.
            return {"count": 437, "count_truncated": False, "pages": []}
        # Page 1's own fetch still has more rows outstanding.
        return {"records": page, "count": len(page), "next_cursor": "page-2-and-beyond"}

    with patch.object(server, "_tracker_api_request", side_effect=fake_request):
        result = _call_tracker_list(
            {"project_id": "enceladus", "record_type": "task", "status": "open", "page_size": 5, "exhaust": True}
        )

    assert result["total"] == 437
    assert "total_is_lower_bound" not in result  # census itself was exact
    assert result["orphan_tasks"] == 1
    assert result["orphan_tasks_is_lower_bound"] is True  # but orphan scan only saw page 1


def test_mode_census_forwards_verbatim_and_bypasses_escalation_reroute():
    """ENC-TSK-Q15 (O3.1): mode=census forwards unchanged with the clamped
    page_size, returns the census payload verbatim under 'result' with no
    'records' key, and never invokes the escalation reroute even when
    record_type=escalation is passed."""
    captured = []

    def fake_request(method, path, payload=None, query=None):
        captured.append((method, path, dict(query) if query else {}))
        return {
            "count": 12,
            "count_truncated": False,
            "exhausted": True,
            "pages": [],
            "page_size": query["page_size"],
            "as_of": {"kind": "wall_clock+max_updated_at", "started_at": "t0", "max_updated_at": "t0"},
            "order": "unspecified",
            "by_type": {"task": 12},
        }

    with patch.object(server, "_tracker_api_request", side_effect=fake_request):
        result = _call_tracker_list(
            {
                "project_id": "enceladus",
                "record_type": "escalation",
                "page_size": 500,
                "mode": "census",
            }
        )

    assert len(captured) == 1
    method, path, query = captured[0]
    assert method == "GET"
    assert path == "/enceladus"
    assert query["mode"] == "census"
    assert query["page_size"] == 100  # clamped 1..100
    assert query["type"] == "escalation"
    assert "records" not in result
    assert result["count"] == 12
    assert result["by_type"] == {"task": 12}


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
