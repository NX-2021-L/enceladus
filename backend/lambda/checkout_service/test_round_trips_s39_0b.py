"""ENC-TSK-S39-0B (W3b.2): pin the number of nested tracker requests per checkout.task /
checkout.advance arc, and the nested_requests field on the [WRITE-AUDIT] line.

BASELINE_* are the request counts measured on v4/main 7aff2645 (before this task); the
assertions on the current code pin the saving so a regression back to the old shape fails.

Run: PYTHONPATH=backend/lambda/shared_layer/python python3 -m pytest backend/lambda/checkout_service/test_round_trips_s39_0b.py -q
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared_layer", "python"))
_SPEC = importlib.util.spec_from_file_location(
    "checkout_lambda_s39_0b", os.path.join(os.path.dirname(__file__), "lambda_function.py"))
co = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = co
_SPEC.loader.exec_module(co)

PROVIDER = "claude-code-s39-0b-test"
SHA = "a" * 40

# (method, step) -> nested _tracker_request calls, measured before the change (7aff2645).
# "checkout" = checkout.task on an unstamped task; "advance:<status>" = one checkout.advance.
BASELINE = {
    "github_pr_deploy": {"checkout": 5, "advance:in-progress": 6, "advance:coding-complete": 4,
                         "advance:committed": 4, "advance:pr": 3, "advance:merged-main": 3,
                         "advance:deploy-init": 3, "advance:deploy-success": 5, "advance:closed": 4},
    "lambda_deploy": {"checkout": 5, "advance:in-progress": 6, "advance:coding-complete": 4,
                      "advance:committed": 4, "advance:pr": 3, "advance:merged-main": 3,
                      "advance:deploy-init": 3, "advance:deploy-success": 5, "advance:closed": 4},
    "web_deploy": {"checkout": 5, "advance:in-progress": 6, "advance:coding-complete": 4,
                   "advance:committed": 4, "advance:pr": 3, "advance:merged-main": 3,
                   "advance:deploy-init": 3, "advance:deploy-success": 5, "advance:closed": 4},
    "code_only": {"checkout": 5, "advance:in-progress": 6, "advance:coding-complete": 4,
                  "advance:committed": 4, "advance:pr": 3, "advance:merged-main": 3,
                  "advance:closed": 4},
    "no_code": {"checkout": 5, "advance:in-progress": 6, "advance:coding-complete": 3,
                "advance:closed": 4},
}
# After this task: only the duplicate GET behind advance(in-progress) is removed on a first
# checkout (the checkout_transition_type stamp is still written for an unstamped task).
EXPECTED = {t: dict(v, **{"advance:in-progress": 5}) for t, v in BASELINE.items()}


class FakeTracker:
    """Stateful stand-in for tracker_mutation behind _tracker_request; records every call."""

    def __init__(self, task: dict):
        self.task = task
        self.calls: list = []

    def __call__(self, method, path, payload=None):
        self.calls.append((method, path))
        if method == "GET":
            return 200, {"success": True, "record": json.loads(json.dumps(self.task))}
        if method == "POST" and path.endswith("/checkout"):
            self.task.update(active_agent_session=True, active_agent_session_id=PROVIDER)
            return 200, {"success": True, "governance_hash": "h"}
        if method == "DELETE" and path.endswith("/checkout"):
            self.task.update(active_agent_session=False, active_agent_session_id="")
            return 200, {"success": True}
        if method == "PATCH":
            self.task[payload["field"]] = payload["value"]
            return 200, {"success": True}
        return 404, {"error": "unexpected"}


def _evidence(arc: str, status: str) -> dict:
    if status == "committed":
        return {"commit_sha": SHA, "owner": "o", "repo": "r"}
    if status == "merged-main":
        return {"pr_id": 1, "merged_at": "2026-11-04T00:00:00Z", "owner": "o", "repo": "r"}
    if status == "deploy-success":
        key = {"github_pr_deploy": "deploy_evidence", "lambda_deploy": "lambda_deploy_evidence",
               "web_deploy": "web_deploy_evidence"}[arc]
        return {key: {"ok": True}}
    if status == "closed":
        if arc == "code_only":
            return {"code_on_main_evidence": {"commit_sha": SHA}, "owner": "o", "repo": "r"}
        return {"no_code_evidence" if arc == "no_code" else "live_validation_evidence": "verified"}
    return {}


def measure_arc(mod, arc: str) -> dict:
    """Run checkout.task + every advance of `arc`; return {step: nested request count}."""
    tracker = FakeTracker({
        "record_id": "task#ENC-TSK-1", "item_id": "ENC-TSK-1", "status": "open", "transition_type": arc,
        "components": ["comp-x"], "active_agent_session": False, "checkout_count": 0,
    })
    counts: dict = {}
    patches = [
        mock.patch.object(mod, "_tracker_request", side_effect=tracker),
        mock.patch.object(mod, "_get_components_lifecycle", return_value={}),
        mock.patch.object(mod, "_get_required_transition_type", return_value=None),
        mock.patch.object(mod, "_get_component_required_transition_types", return_value=set()),
        mock.patch.object(mod, "_store_token"), mock.patch.object(mod, "_delete_token"),
        mock.patch.object(mod, "_validate_commit", return_value=(True, "")),
        mock.patch.object(mod, "_validate_pr_merged", return_value=(True, "")),
        mock.patch.object(mod, "_validate_code_on_main_evidence", return_value=(True, "")),
        mock.patch.dict(mod._DEPLOY_SUCCESS_VALIDATORS, {a: (lambda e: (True, "")) for a in
                                                         ("github_pr_deploy", "lambda_deploy", "web_deploy")}),
    ]
    with contextlib.ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        resp = mod._handle_checkout("enceladus", "ENC-TSK-1", {"active_agent_session_id": PROVIDER})
        assert resp["statusCode"] == 200, resp
        counts["checkout"] = len(tracker.calls)
        # advance(in-progress) on a fresh, unstamped, un-checked-out copy of the task
        t2 = FakeTracker({**tracker.task, "active_agent_session": False, "checkout_transition_type": ""})
        t2.task.pop("checkout_transition_type")
        with mock.patch.object(mod, "_tracker_request", side_effect=t2):
            r = mod._handle_advance("enceladus", "ENC-TSK-1", {
                "target_status": "in-progress", "provider": PROVIDER, "governance_hash": "h",
                "active_agent_session_id": PROVIDER})
            assert r["statusCode"] == 200, r
        counts["advance:in-progress"] = len(t2.calls)
        for status in mod.ALLOWED_TRANSITIONS_BY_TYPE[arc][1:]:
            before = len(tracker.calls)
            r = mod._handle_advance("enceladus", "ENC-TSK-1", {
                "target_status": status, "provider": PROVIDER, "governance_hash": "h",
                "transition_evidence": _evidence(arc, status)})
            assert r["statusCode"] == 200, (status, r)
            counts[f"advance:{status}"] = len(tracker.calls) - before
    return counts


class RoundTripsPerArcTests(unittest.TestCase):
    def test_requests_per_step_pinned_per_arc(self):
        for arc, expected in EXPECTED.items():
            with self.subTest(arc=arc):
                self.assertEqual(measure_arc(co, arc), expected)

    def test_never_more_than_baseline(self):
        for arc, baseline in BASELINE.items():
            got = measure_arc(co, arc)
            for step, n in got.items():
                self.assertLessEqual(n, baseline[step], (arc, step))
        # the saving itself: the duplicate GET behind advance(in-progress) is gone
        self.assertEqual(measure_arc(co, "no_code")["advance:in-progress"],
                         BASELINE["no_code"]["advance:in-progress"] - 1)

    def test_advance_in_progress_reads_task_once(self):
        tracker = FakeTracker({"item_id": "ENC-TSK-1", "status": "open", "transition_type": "no_code",
                               "components": [], "active_agent_session": False})
        with mock.patch.object(co, "_tracker_request", side_effect=tracker):
            r = co._handle_advance("enceladus", "ENC-TSK-1", {
                "target_status": "in-progress", "provider": PROVIDER, "user_initiated": True,
                "active_agent_session_id": PROVIDER})
        self.assertEqual(r["statusCode"], 200)
        # pre-read once (not twice), then checkout POST, status PATCH, post-read, stamp PATCH
        self.assertEqual([m for m, _ in tracker.calls], ["GET", "POST", "PATCH", "GET", "PATCH"])

    def test_recheckout_skips_identical_stamp(self):
        tracker = FakeTracker({"item_id": "ENC-TSK-1", "status": "in-progress", "transition_type": "no_code",
                               "checkout_transition_type": "no_code", "components": [],
                               "active_agent_session": False})
        with mock.patch.object(co, "_tracker_request", side_effect=tracker):
            r = co._handle_checkout("enceladus", "ENC-TSK-1", {"active_agent_session_id": PROVIDER})
        self.assertEqual(r["statusCode"], 200)
        self.assertEqual([m for m, _ in tracker.calls], ["GET", "POST", "PATCH", "GET"])
        self.assertEqual(json.loads(r["body"])["checkout_transition_type"], "no_code")

    def test_failure_gate_write_skipped_only_when_unchanged(self):
        with mock.patch.object(co, "_tracker_request", return_value=(200, {})) as tr:
            n = co._increment_failure_count("p", "T", {"advance_failure_gate": "g", "advance_failure_count": 1}, "g", PROVIDER)
            self.assertEqual((n, tr.call_count), (2, 1))
            tr.reset_mock()
            n = co._increment_failure_count("p", "T", {"advance_failure_gate": "other", "advance_failure_count": 2}, "g", PROVIDER)
            self.assertEqual((n, tr.call_count), (1, 2))

    def test_subtask_gate_reads_children_concurrently_in_order(self):
        statuses = {"C1": "closed", "C2": "pr", "C3": "closed", "C4": "pr"}
        seen = []

        def fake(method, path, payload=None):
            cid = path.rsplit("/", 1)[-1]
            seen.append(cid)
            return 200, {"record": {"status": statuses[cid]}}

        with mock.patch.object(co, "_tracker_request", side_effect=fake):
            err = co._validate_subtask_gate("p", "T", {"subtask_ids": list(statuses), "status": "pr"}, "coding-complete")
        self.assertIsNone(err)
        self.assertEqual(sorted(seen), sorted(statuses))
        statuses["C2"] = "open"
        with mock.patch.object(co, "_tracker_request", side_effect=fake):
            err = co._validate_subtask_gate("p", "T", {"subtask_ids": list(statuses), "status": "pr"}, "closed")
        lagging = json.loads(err["body"]).get("details", {}).get("lagging_subtasks") or json.loads(err["body"])
        self.assertIn("C2", json.dumps(lagging))
        self.assertIn("C4", json.dumps(lagging))
        self.assertLess(json.dumps(lagging).index("C2"), json.dumps(lagging).index("C4"))


class _Ctx:
    aws_request_id = "req-s39"
    memory_limit_in_mb = 256
    function_version = "$LATEST"


class _Resp:
    status = 200

    def read(self):
        return b"{}"

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class NestedRequestsTelemetryTests(unittest.TestCase):
    def test_write_audit_line_counts_nested_requests(self):
        def inner(event, context):
            with mock.patch.object(co.urllib.request, "urlopen", lambda req, timeout=0: _Resp()):
                co._tracker_request("GET", "/enceladus/task/ENC-TSK-1")
                co._tracker_request("PATCH", "/enceladus/task/ENC-TSK-1", {"field": "status", "value": "x"})
                co._tracker_request("GET", "/enceladus/task/ENC-TSK-1")
            return {"statusCode": 200, "body": "{}"}
        ev = {"requestContext": {"http": {"method": "POST", "path": "/api/v1/checkout/enceladus/task/ENC-TSK-1/advance"}},
              "headers": {}, "body": "{}"}
        buf = io.StringIO()
        with mock.patch.object(co, "_lambda_handler_inner", inner), contextlib.redirect_stdout(buf):
            co.lambda_handler(ev, _Ctx())
        line = json.loads(buf.getvalue().split("[WRITE-AUDIT] ", 1)[1])
        self.assertEqual(line["nested_requests"], 3)

    def test_no_requests_reports_zero(self):
        ev = {"requestContext": {"http": {"method": "POST", "path": "/api/v1/checkout/enceladus/task/ENC-TSK-1/advance"}},
              "headers": {}, "body": "{}"}
        buf = io.StringIO()
        with mock.patch.object(co, "_lambda_handler_inner", lambda e, c: {"statusCode": 400, "body": "{}"}), \
                contextlib.redirect_stdout(buf):
            co.lambda_handler(ev, _Ctx())
        self.assertEqual(json.loads(buf.getvalue().split("[WRITE-AUDIT] ", 1)[1])["nested_requests"], 0)


if __name__ == "__main__":
    unittest.main()
