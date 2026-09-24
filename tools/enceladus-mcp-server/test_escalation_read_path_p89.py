"""Unit tests for ENC-TSK-P89 (ENC-ISS-699): the MCP server's escalation
(and generation) read path.

Covers:
  (a) _parse_record_id resolves an ENC-ESC-* id to record_type="escalation"
      instead of raising "Unknown type segment" (the ENC-ISS-699 symptom)
  (b) _tracker_key builds the same "escalation#ENC-ESC-NNN" sort key shape
      tracker_mutation/lambda_function.py stores escalations under
  (c) an ENC-GEN-* id resolves to record_type="generation"
  (d) _tracker_list(record_type="escalation") walks next_cursor past a
      single page and reports a `total` matching the true record count
      (regression for the "capped at ENC-ESC-050" pagination defect)

Related: ENC-TSK-P89, ENC-ISS-699, ENC-ISS-759 (sibling fix, different file)
"""
import asyncio
import importlib.util
import json
import pathlib
import sys

import pytest

MODULE_PATH = pathlib.Path(__file__).with_name("server.py")
SPEC = importlib.util.spec_from_file_location("enceladus_server_escalation_read_unit", MODULE_PATH)
server = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = server
SPEC.loader.exec_module(server)


@pytest.fixture(autouse=True)
def _stub_prefix_resolution(monkeypatch):
    """Every test resolves the ENC prefix to 'enceladus' without a live API call."""
    monkeypatch.setattr(server, "_resolve_prefix", lambda prefix: {"ENC": "enceladus"}[prefix])
    yield


def test_parse_record_id_resolves_escalation():
    assert server._parse_record_id("ENC-ESC-099") == ("enceladus", "escalation", "ENC-ESC-099")


def test_parse_record_id_resolves_generation():
    assert server._parse_record_id("ENC-GEN-001") == ("enceladus", "generation", "ENC-GEN-001")


def test_tracker_key_builds_escalation_sort_key():
    key = server._tracker_key("ENC-ESC-099")
    assert key["record_id"]["S"] == "escalation#ENC-ESC-099"
    assert key["project_id"]["S"] == "enceladus"


def test_tracker_key_builds_generation_sort_key():
    key = server._tracker_key("ENC-GEN-001")
    assert key["record_id"]["S"] == "generation#ENC-GEN-001"


def test_unknown_segment_still_raises():
    with pytest.raises(ValueError, match="Unknown type segment"):
        server._parse_record_id("ENC-ZZZ-001")


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _esc_item(n):
    esc_id = f"ENC-ESC-{n:03d}"
    return {"item_id": esc_id, "record_type": "escalation", "status": "requested",
            "created_at": f"2026-07-02T00:{n % 60:02d}:00Z"}


def test_tracker_list_escalation_paginates_past_a_single_page(monkeypatch):
    """ENC-TSK-Q15 (O3.3): tracker.list(record_type="escalation", exhaust=True)
    no longer walks next_cursor across the dedicated /escalation/list endpoint
    itself -- it gets the true total from the census fast path (mode=census,
    which per D5 covers escalations via its own bounded server-side walk over
    the base project route, NOT /escalation/list) and then fetches only page 1
    of rows from /escalation/list as before. This is the regression coverage
    for the original "capped at ENC-ESC-050" pagination defect, now expressed
    against the census-backed contract instead of a client-side page walk."""
    calls = []

    def _fake_tracker_api_request(method, path, query=None, **kwargs):
        assert method == "GET"
        calls.append((path, query.get("next_cursor") if query else None))
        if path == "/enceladus":
            assert query.get("mode") == "census"
            return {"count": 75, "count_truncated": False, "pages": []}
        assert path == "/enceladus/escalation/list"
        return {"escalations": [_esc_item(n) for n in range(1, 26)], "next_cursor": "cur1"}

    monkeypatch.setattr(server, "_tracker_api_request", _fake_tracker_api_request)

    result_text = _run(server._tracker_list({
        "project_id": "enceladus",
        "record_type": "escalation",
        "page_size": 25,
        "exhaust": True,
    }))
    result = json.loads(result_text[0].text)

    assert calls == [("/enceladus", None), ("/enceladus/escalation/list", None)]
    assert result["total"] == 75
    assert "total_is_lower_bound" not in result
    assert "exhaustion_truncated" not in result
    ids = {rec["id"] for rec in result["records"]}
    assert "ENC-ESC-025" in ids


def test_tracker_list_escalation_single_page_reports_lower_bound(monkeypatch):
    """Without exhaust, a next_cursor from the dedicated endpoint still marks
    total as a lower bound rather than silently under-reporting it as exact."""
    def _fake_tracker_api_request(method, path, query=None, **kwargs):
        assert path == "/enceladus/escalation/list"
        return {"escalations": [_esc_item(n) for n in range(1, 26)], "next_cursor": "cur1"}

    monkeypatch.setattr(server, "_tracker_api_request", _fake_tracker_api_request)

    result_text = _run(server._tracker_list({
        "project_id": "enceladus", "record_type": "escalation", "page_size": 25,
    }))
    result = json.loads(result_text[0].text)
    assert result["total_is_lower_bound"] is True
    assert result["next_cursor"] == "cur1"


def _esc_backend_get_response():
    """The real _handle_escalation_get shape: {"success": True, "escalation": {...}}
    -- fields live one level deeper than every other record type's {"record": {...}}."""
    return {
        "success": True,
        "escalation": {
            "item_id": "ENC-ESC-042",
            "record_type": "escalation",
            "status": "requested",
            "title": "Escalation title",
            "priority": "P1",
            "category": "escalation",
            "intent": "direct_state_override",
            "payload": {"target_status": "closed"},
        },
    }


def test_tracker_get_unwraps_escalation_envelope(monkeypatch):
    """ENC-TSK-P89: _tracker_get must read the escalation body out of
    resp["escalation"], not fall through to the whole wrapper because there
    is no "record" key."""
    monkeypatch.setattr(
        server, "_tracker_api_request",
        lambda method, path, **kwargs: _esc_backend_get_response(),
    )
    result_text = _run(server._tracker_get({"record_id": "ENC-ESC-042"}))
    record = json.loads(result_text[0].text)
    assert record["status"] == "requested"
    assert record["title"] == "Escalation title"
    assert record["priority"] == "P1"
    assert record.get("success") is not True  # not the raw wrapper
    assert "escalation" not in record  # unwrapped, not nested


def test_get_issue_context_unwraps_escalation_envelope(monkeypatch):
    """ENC-TSK-P89: get_issue_context (get_compact_context mode=record) hit the
    identical bug -- record_core ended up with title/status/priority/category/
    intent all empty for a real escalation."""
    monkeypatch.setattr(
        server, "_tracker_api_request",
        lambda method, path, **kwargs: _esc_backend_get_response(),
    )
    result_text = _run(server._get_issue_context({
        "record_id": "ENC-ESC-042",
        "include_components": False,
        "include_architecture": False,
        "include_recent_history": False,
    }))
    result = json.loads(result_text[0].text)
    record_core = result["record"]
    assert record_core["status"] == "requested"
    assert record_core["title"] == "Escalation title"
    assert record_core["priority"] == "P1"
    assert record_core["category"] == "escalation"
    assert record_core["intent"] == "direct_state_override"
