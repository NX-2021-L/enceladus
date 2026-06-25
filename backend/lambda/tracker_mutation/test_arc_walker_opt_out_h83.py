"""Tests for ENC-TSK-H83 / ENC-FTR-111 — auto_walk_opt_out circuit breaker.

Covers FTR-111 AC-2: the field exists (dictionary, validated separately), the write path
auto-latches it true on a human-initiated non-forward transition and emits an Artifact-Genesis
record, it is settable/clearable via the generic write path, and the arc-walker can NEVER clear it.

Pure-logic units plus integration over the two human write paths, mocking DynamoDB/EventBridge.
Runs standalone (python test_arc_walker_opt_out_h83.py) or under pytest.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lambda_function as lf  # noqa: E402


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------
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


def _status_update(ddb):
    """The status-change update_item (the one carrying transition_evidence)."""
    for u in ddb.updates:
        if "transition_evidence = :te" in u.get("UpdateExpression", ""):
            return u
    return None


# ---------------------------------------------------------------------------
# Pure logic
# ---------------------------------------------------------------------------
def test_coerce_bool():
    assert lf._coerce_bool(True) is True
    assert lf._coerce_bool(False) is False
    assert lf._coerce_bool("true") is True
    assert lf._coerce_bool("false") is False
    assert lf._coerce_bool("FALSE") is False
    assert lf._coerce_bool("1") is True
    assert lf._coerce_bool("0") is False
    assert lf._coerce_bool(0) is False
    assert lf._coerce_bool(1) is True
    assert lf._coerce_bool("yes") is True


def test_is_human_request():
    assert lf._is_human_request({"auth_mode": "user"}) is True
    assert lf._is_human_request({"auth_mode": "internal-key"}) is False
    assert lf._is_human_request(None) is False
    assert lf._is_human_request({}) is False


def test_is_task_non_forward():
    # regressions
    assert lf._is_task_non_forward("deploy-success", "in-progress") == (True, "regression")
    assert lf._is_task_non_forward("committed", "coding-complete") == (True, "regression")
    assert lf._is_task_non_forward("pr", "open") == (True, "regression")
    # coding-updates re-entry (no forward rank — explicit)
    assert lf._is_task_non_forward("deploy-success", "coding-updates") == (True, "coding-updates re-entry")
    # forward / same / no-op
    assert lf._is_task_non_forward("open", "in-progress") == (False, "")
    assert lf._is_task_non_forward("in-progress", "closed") == (False, "")
    assert lf._is_task_non_forward("in-progress", "in-progress") == (False, "")


# ---------------------------------------------------------------------------
# Walker-can-never-clear guard (AC-2) — returns before any DB read
# ---------------------------------------------------------------------------
def test_walker_cannot_clear_opt_out():
    body = {"field": "auto_walk_opt_out", "value": False,
            "write_source": {"provider": "system:arc-walker"}}
    resp = lf._handle_update_field("enceladus", "task", "ENC-TSK-X", body)
    assert resp["statusCode"] == 403, resp
    payload = json.loads(resp["body"])
    assert payload["error_envelope"]["code"] == "ARC_WALKER_OPT_OUT_IMMUTABLE", payload


def test_walker_clear_blocked_via_channel():
    body = {"field": "auto_walk_opt_out", "value": "false",
            "write_source": {"channel": "system:arc-walker"}}
    resp = lf._handle_update_field("enceladus", "task", "ENC-TSK-X", body)
    assert resp["statusCode"] == 403, resp


def test_walker_may_set_true():
    # Latching true (not clearing) is permitted even from the walker actor.
    ddb, _ = _install(raw_item={"status": {"S": "open"}, "active_agent_session": {"BOOL": False}})
    body = {"field": "auto_walk_opt_out", "value": True,
            "write_source": {"provider": "system:arc-walker"}}
    resp = lf._handle_update_field("enceladus", "task", "ENC-TSK-X", body)
    assert resp["statusCode"] == 200, resp
    assert ddb.updates and ddb.updates[-1]["ExpressionAttributeValues"][":val"] == {"BOOL": True}


# ---------------------------------------------------------------------------
# Settable/clearable via the generic write path (BOOL coercion)
# ---------------------------------------------------------------------------
def test_human_clear_allowed_and_coerced_to_bool():
    ddb, _ = _install(raw_item={"status": {"S": "open"}, "active_agent_session": {"BOOL": False}})
    body = {"field": "auto_walk_opt_out", "value": "false",
            "write_source": {"provider": "io"}}
    resp = lf._handle_update_field("enceladus", "task", "ENC-TSK-X", body)
    assert resp["statusCode"] == 200, resp
    assert ddb.updates[-1]["ExpressionAttributeValues"][":val"] == {"BOOL": False}


# ---------------------------------------------------------------------------
# Auto-latch on human non-forward (task user_initiated path) — AC-2 + AC-4
# ---------------------------------------------------------------------------
def test_human_non_forward_latches_and_emits_artifact_genesis():
    ddb, events = _install()
    claims = {"auth_mode": "user", "cognito:username": "io"}
    item_data = {"status": "deploy-success", "active_agent_session": False, "active_agent_session_id": ""}
    body = {"value": "coding-updates",
            "transition_evidence": {"user_note": "reopen for a follow-up fix"}}
    resp = lf._apply_user_initiated_advance("enceladus", "task", "ENC-TSK-X", body, item_data, claims)
    assert resp["statusCode"] == 200, resp
    su = _status_update(ddb)
    assert su is not None, ddb.updates
    assert "auto_walk_opt_out = :optout" in su["UpdateExpression"], su["UpdateExpression"]
    assert su["ExpressionAttributeValues"][":optout"] == {"BOOL": True}
    # Artifact-Genesis: a latch history entry rode the same write, and a telemetry event fired.
    hist = su["ExpressionAttributeValues"][":hentry"]["L"]
    assert any("[ARC-WALKER][OPT-OUT-LATCH]" in h["M"]["description"]["S"] for h in hist), hist
    assert len(events.events) == 1, events.events
    detail = json.loads(events.events[0]["Entries"][0]["Detail"])
    assert detail["event"] == "auto_walk_opt_out_latched"
    assert detail["trigger"] == "coding-updates re-entry"
    assert detail["to_status"] == "coding-updates"


def test_human_forward_does_not_latch():
    ddb, events = _install()
    claims = {"auth_mode": "user", "cognito:username": "io"}
    item_data = {"status": "in-progress", "active_agent_session": False, "active_agent_session_id": ""}
    body = {"value": "coding-complete",
            "transition_evidence": {"user_note": "advancing normally"}}
    resp = lf._apply_user_initiated_advance("enceladus", "task", "ENC-TSK-X", body, item_data, claims)
    assert resp["statusCode"] == 200, resp
    for u in ddb.updates:
        assert ":optout" not in u.get("ExpressionAttributeValues", {}), u
    assert events.events == [], events.events


if __name__ == "__main__":
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    failed = 0
    for fn in fns:
        # fresh fakes per test
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
