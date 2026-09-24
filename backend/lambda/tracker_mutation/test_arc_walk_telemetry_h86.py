"""Tests for ENC-TSK-H86 / ENC-FTR-111 Phase 1 (T5) — ARC_WALK opt_out latch/clear telemetry.

Covers FTR-111 AC-6 (this task's AC-1): an EXPLICIT human/agent tracker.set of auto_walk_opt_out
emits a governed latch-or-clear telemetry event AND a [ARC-WALKER][OPT-OUT-SET|OPT-OUT-CLEAR]
history marker, so both states reach the ENC-TSK-B66 observability dashboard. The H83 auto-latch
path (covered by test_arc_walker_opt_out_h83.py) and the H85 ARC_WALK advance event
(test_arc_walker_phase1_h85.py) are the other two telemetry legs.

Pure-logic units plus integration over the generic write path, mocking DynamoDB/EventBridge.
Runs standalone (python test_arc_walk_telemetry_h86.py) or under pytest.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lambda_function as lf  # noqa: E402


class _FakeDDB:
    def __init__(self):
        self.updates = []

    def update_item(self, **kw):
        self.updates.append(kw)
        return {}

    def get_item(self, **kw):
        return {}


class _FakeEvents:
    def __init__(self):
        self.events = []

    def put_events(self, **kw):
        self.events.append(kw)
        return {"FailedEntryCount": 0}


def _install(ddb=None, events=None, raw_item="__keep__"):
    ddb = ddb or _FakeDDB()
    events = events or _FakeEvents()
    lf._get_ddb = lambda: ddb            # type: ignore
    lf._get_events = lambda: events      # type: ignore
    lf._build_key = lambda p, t, r: {"project_id": {"S": p}, "record_id": {"S": f"{t}#{r}"}}  # type: ignore
    if raw_item != "__keep__":
        lf._get_record_raw = lambda p, t, r: raw_item  # type: ignore
    return ddb, events


# ---------------------------------------------------------------------------
# Pure logic — history-entry markers
# ---------------------------------------------------------------------------
def test_opt_out_state_history_entry_markers():
    set_entry = lf._opt_out_state_history_entry("2026-06-30T00:00:00Z", True, "io")
    assert "[ARC-WALKER][OPT-OUT-SET]" in set_entry["M"]["description"]["S"]
    clr_entry = lf._opt_out_state_history_entry("2026-06-30T00:00:00Z", False, "io")
    assert "[ARC-WALKER][OPT-OUT-CLEAR]" in clr_entry["M"]["description"]["S"]


def test_opt_out_state_event_detail_shape():
    events = _FakeEvents()
    lf._get_events = lambda: events  # type: ignore
    lf._emit_opt_out_state_event("enceladus", "task", "ENC-TSK-X", True, "io")
    lf._emit_opt_out_state_event("enceladus", "task", "ENC-TSK-X", False, "io")
    assert len(events.events) == 2
    latched = json.loads(events.events[0]["Entries"][0]["Detail"])
    cleared = json.loads(events.events[1]["Entries"][0]["Detail"])
    assert latched["event"] == "auto_walk_opt_out_latched"
    assert latched["latched"] is True and latched["trigger"] == "explicit_set"
    assert cleared["event"] == "auto_walk_opt_out_cleared"
    assert cleared["latched"] is False and cleared["trigger"] == "explicit_clear"
    # The clear event rides the dedicated cleared DetailType.
    assert events.events[1]["Entries"][0]["DetailType"] == lf.EVENT_DETAIL_TYPE_OPT_OUT_CLEARED


# ---------------------------------------------------------------------------
# Integration — explicit set/clear via the generic write path
# ---------------------------------------------------------------------------
def test_explicit_clear_emits_clear_event_and_marker():
    ddb, events = _install(raw_item={"status": {"S": "open"}, "active_agent_session": {"BOOL": False}})
    body = {"field": "auto_walk_opt_out", "value": "false", "write_source": {"provider": "io"}}
    resp = lf._handle_update_field("enceladus", "task", "ENC-TSK-X", body)
    assert resp["statusCode"] == 200, resp
    # BOOL coercion + clear event.
    assert ddb.updates[-1]["ExpressionAttributeValues"][":val"] == {"BOOL": False}
    hist = ddb.updates[-1]["ExpressionAttributeValues"][":hentry"]["L"]
    assert any("[ARC-WALKER][OPT-OUT-CLEAR]" in h["M"]["description"]["S"] for h in hist), hist
    assert len(events.events) == 1, events.events
    detail = json.loads(events.events[0]["Entries"][0]["Detail"])
    assert detail["event"] == "auto_walk_opt_out_cleared"
    assert detail["actor"] == "io"


def test_explicit_set_true_emits_latch_event_and_marker():
    ddb, events = _install(raw_item={"status": {"S": "open"}, "active_agent_session": {"BOOL": False}})
    body = {"field": "auto_walk_opt_out", "value": True, "write_source": {"provider": "io"}}
    resp = lf._handle_update_field("enceladus", "task", "ENC-TSK-X", body)
    assert resp["statusCode"] == 200, resp
    assert ddb.updates[-1]["ExpressionAttributeValues"][":val"] == {"BOOL": True}
    hist = ddb.updates[-1]["ExpressionAttributeValues"][":hentry"]["L"]
    assert any("[ARC-WALKER][OPT-OUT-SET]" in h["M"]["description"]["S"] for h in hist), hist
    assert len(events.events) == 1, events.events
    detail = json.loads(events.events[0]["Entries"][0]["Detail"])
    assert detail["event"] == "auto_walk_opt_out_latched"
    assert detail["trigger"] == "explicit_set"


def test_non_opt_out_field_emits_no_opt_out_event():
    ddb, events = _install(raw_item={"status": {"S": "open"}, "active_agent_session": {"BOOL": False}})
    body = {"field": "priority", "value": "P2", "write_source": {"provider": "io"}}
    resp = lf._handle_update_field("enceladus", "task", "ENC-TSK-X", body)
    assert resp["statusCode"] == 200, resp
    assert events.events == [], events.events


if __name__ == "__main__":
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    failed = 0
    for fn in fns:
        _install(raw_item="__keep__")
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
