"""ENC-TSK-J69 (ENC-FTR-121 Ph2): applyEscalatedMutation applier tests.

The applier is the single privileged code path allowed to write transitions
the normal FSM forbids (DOC-5B888FCA43B8 Tenet 2) — the last line of defense,
so it carries the feature's heaviest test weight: exactly-once semantics via
the applied_at guard and the conditional approved→applying gate, the full
approved→applying→applied|failed FSM walk with §11.2 events, checkout
survival under deploy_arc_change, path-illegal direct_state_override
(coding-complete→closed AND closed→pr), §5.6 escalation_waived sentinels,
escalated_closure, provenance stamping, no-partial-write failure handling,
and negative assertions that the normal validators acquired no bypass.
"""
import json
import unittest
from unittest import mock

from botocore.exceptions import ClientError


def _ccfe():
    return ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException"}}, "UpdateItem")


def _escalation_item(status="approved", mutation_type="deploy_arc_change",
                     payload=None, target="ENC-TSK-J10", applied_at=None):
    if payload is None:
        payload = {"new_deploy_arc_type": "code_only"}
    item = {
        "project_id": {"S": "enceladus"},
        "record_id": {"S": "escalation#ENC-ESC-001"},
        "item_id": {"S": "ENC-ESC-001"},
        "record_type": {"S": "escalation"},
        "status": {"S": status},
        "mutation_type": {"S": mutation_type},
        "target_record_id": {"S": target},
        "payload": {"S": json.dumps(payload)},
        "justification": {"S": "test"},
        "requested_by": {"M": {
            "session_id": {"S": "ENC-SES-02F"},
            "agent_type_id": {"S": "ENC-AGT-006"},
            "sci_present": {"BOOL": False},
        }},
        "approved_by": {"M": {"email": {"S": "io@jreese.net"}, "sub": {"S": "abc-123"}}},
        "events": {"L": []},
        "created_at": {"S": "2026-07-02T04:00:00Z"},
        "updated_at": {"S": "2026-07-02T04:00:00Z"},
    }
    if applied_at:
        item["applied_at"] = {"S": applied_at}
    return item


def _target_task(status="in-progress", transition_type="github_pr_deploy",
                 checked_out=True, record_id="ENC-TSK-J10"):
    item = {
        "project_id": {"S": "enceladus"},
        "record_id": {"S": f"task#{record_id}"},
        "item_id": {"S": record_id},
        "record_type": {"S": "task"},
        "status": {"S": status},
        "title": {"S": "target"},
        "transition_type": {"S": transition_type},
    }
    if checked_out:
        item["checkout_state"] = {"S": "checked_out"}
        item["checked_out_by"] = {"S": "ENC-SES-02C"}
        item["checked_out_at"] = {"S": "2026-07-02T03:00:00Z"}
        item["active_agent_session_id"] = {"S": "ENC-SES-02C"}
        item["checkout_transition_type"] = {"S": transition_type}
    return item


class _FakeDdb:
    """Routes get_item by record_id; records every update_item call."""

    def __init__(self, escalation=None, target=None,
                 fail_first_update=False, fail_target_update=False):
        self.escalation = escalation
        self.target = target
        self.updates = []
        self._fail_first_update = fail_first_update
        self._fail_target_update = fail_target_update
        self.exceptions = mock.MagicMock()

    def get_item(self, TableName=None, Key=None, **kwargs):
        record_id = (Key or {}).get("record_id", {}).get("S", "")
        if record_id.startswith("escalation#") and self.escalation is not None:
            return {"Item": self.escalation}
        if record_id.startswith(("task#", "issue#", "feature#")) and self.target is not None:
            return {"Item": self.target}
        return {}

    def update_item(self, **kwargs):
        record_id = kwargs.get("Key", {}).get("record_id", {}).get("S", "")
        if self._fail_first_update and not self.updates:
            self.updates.append(kwargs)
            raise _ccfe()
        if self._fail_target_update and not record_id.startswith("escalation#"):
            self.updates.append(kwargs)
            raise RuntimeError("forced target write failure")
        self.updates.append(kwargs)
        return {}

    def escalation_updates(self):
        return [u for u in self.updates
                if u["Key"]["record_id"]["S"].startswith("escalation#")]

    def target_updates(self):
        return [u for u in self.updates
                if not u["Key"]["record_id"]["S"].startswith("escalation#")]


class _ApplierBase(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf
        self._patches = [
            mock.patch.object(lf, "ENABLE_ESCALATION_PRIMITIVE", True),
            mock.patch.object(lf, "_get_events", return_value=mock.MagicMock()),
        ]
        for patch in self._patches:
            patch.start()

    def tearDown(self):
        for patch in self._patches:
            patch.stop()

    def _apply(self, ddb, body=None):
        with mock.patch.object(self.lf, "_get_ddb", return_value=ddb):
            return self.lf._handle_escalation_apply(
                "enceladus", "ENC-ESC-001",
                body or {"write_source": {"provider": "ENC-SES-02F"}})


class TestApplierGuards(_ApplierBase):
    def test_already_applied_no_ops_without_any_write(self):
        ddb = _FakeDdb(escalation=_escalation_item(
            status="applied", applied_at="2026-07-02T04:05:00Z"))
        resp = self._apply(ddb)
        self.assertEqual(200, resp["statusCode"])
        body = json.loads(resp["body"])
        self.assertTrue(body["no_op"])
        self.assertEqual([], ddb.updates)

    def test_applied_at_set_but_status_stale_still_no_ops(self):
        ddb = _FakeDdb(escalation=_escalation_item(
            status="applying", applied_at="2026-07-02T04:05:00Z"))
        resp = self._apply(ddb)
        self.assertTrue(json.loads(resp["body"])["no_op"])
        self.assertEqual([], ddb.updates)

    def test_requested_status_refused_409(self):
        ddb = _FakeDdb(escalation=_escalation_item(status="requested"))
        resp = self._apply(ddb)
        self.assertEqual(409, resp["statusCode"])
        self.assertIn("not 'approved'", json.loads(resp["body"])["error"])
        self.assertEqual([], ddb.updates)

    def test_denied_status_refused_409(self):
        ddb = _FakeDdb(escalation=_escalation_item(status="denied"))
        resp = self._apply(ddb)
        self.assertEqual(409, resp["statusCode"])
        self.assertEqual([], ddb.updates)

    def test_missing_escalation_404(self):
        ddb = _FakeDdb(escalation=None)
        resp = self._apply(ddb)
        self.assertEqual(404, resp["statusCode"])

    def test_concurrent_applier_losing_race_no_ops(self):
        ddb = _FakeDdb(escalation=_escalation_item(),
                       target=_target_task(), fail_first_update=True)
        resp = self._apply(ddb)
        self.assertEqual(200, resp["statusCode"])
        body = json.loads(resp["body"])
        self.assertTrue(body["no_op"])
        self.assertIn("concurrent", body["reason"])
        # Only the losing conditional write was attempted — target untouched.
        self.assertEqual([], ddb.target_updates())

    def test_double_sequential_apply_is_exactly_once(self):
        first = _FakeDdb(escalation=_escalation_item(), target=_target_task())
        resp1 = self._apply(first)
        self.assertEqual(200, resp1["statusCode"])
        self.assertEqual(1, len(first.target_updates()))
        # Second invocation sees the applied state; must be a pure no-op.
        second = _FakeDdb(escalation=_escalation_item(
            status="applied", applied_at="2026-07-02T04:06:00Z"))
        resp2 = self._apply(second)
        self.assertTrue(json.loads(resp2["body"])["no_op"])
        self.assertEqual([], second.updates)

    def test_flag_off_503(self):
        ddb = _FakeDdb(escalation=_escalation_item(), target=_target_task())
        with mock.patch.object(self.lf, "ENABLE_ESCALATION_PRIMITIVE", False):
            resp = self._apply(ddb)
        self.assertEqual(503, resp["statusCode"])
        self.assertEqual([], ddb.updates)


class TestApplierFsmWalk(_ApplierBase):
    def test_success_walks_applying_then_applied_with_events(self):
        ddb = _FakeDdb(escalation=_escalation_item(), target=_target_task())
        resp = self._apply(ddb)
        self.assertEqual(200, resp["statusCode"])
        body = json.loads(resp["body"])
        self.assertEqual("applied", body["status"])
        self.assertTrue(body["applied_at"])
        esc_updates = ddb.escalation_updates()
        self.assertEqual(2, len(esc_updates))
        applying, applied = esc_updates
        self.assertEqual({"S": "applying"},
                         applying["ExpressionAttributeValues"][":to_status"])
        self.assertIn("attribute_not_exists(applied_at)",
                      applying["ConditionExpression"])
        applying_event = applying["ExpressionAttributeValues"][":event"]["L"][0]["M"]
        self.assertEqual("applying", applying_event["event_type"]["S"])
        self.assertEqual({"S": "applied"},
                         applied["ExpressionAttributeValues"][":to_status"])
        self.assertIn("applied_at = :applied_at",
                      applied["UpdateExpression"])
        self.assertEqual("result",
                         applied["ExpressionAttributeNames"]["#res"])
        applied_event = applied["ExpressionAttributeValues"][":event"]["L"][0]["M"]
        self.assertEqual("applied", applied_event["event_type"]["S"])

    def test_missing_target_fails_escalation_with_error_result(self):
        ddb = _FakeDdb(escalation=_escalation_item(), target=None)
        resp = self._apply(ddb)
        self.assertEqual(409, resp["statusCode"])
        esc_updates = ddb.escalation_updates()
        self.assertEqual(2, len(esc_updates))
        failed = esc_updates[1]
        self.assertEqual({"S": "failed"},
                         failed["ExpressionAttributeValues"][":to_status"])
        result = failed["ExpressionAttributeValues"][":result"]
        self.assertIn("not found", json.dumps(result))
        self.assertEqual([], ddb.target_updates())

    def test_handler_exception_fails_escalation_no_partial_target_write(self):
        ddb = _FakeDdb(escalation=_escalation_item(), target=_target_task(),
                       fail_target_update=True)
        resp = self._apply(ddb)
        self.assertEqual(409, resp["statusCode"])
        failed = ddb.escalation_updates()[1]
        self.assertEqual({"S": "failed"},
                         failed["ExpressionAttributeValues"][":to_status"])
        result_json = json.dumps(failed["ExpressionAttributeValues"][":result"])
        self.assertIn("forced target write failure", result_json)
        # The single atomic target UpdateItem raised — nothing partial landed.
        self.assertEqual(1, len(ddb.target_updates()))

    def test_unknown_mutation_type_500_before_any_transition(self):
        ddb = _FakeDdb(escalation=_escalation_item(mutation_type="mystery"))
        resp = self._apply(ddb)
        self.assertEqual(500, resp["statusCode"])
        self.assertEqual([], ddb.updates)

    def test_applied_emits_audit_event(self):
        events_client = mock.MagicMock()
        ddb = _FakeDdb(escalation=_escalation_item(), target=_target_task())
        with mock.patch.object(self.lf, "_get_events", return_value=events_client):
            resp = self._apply(ddb)
        self.assertEqual(200, resp["statusCode"])
        entry = events_client.put_events.call_args.kwargs["Entries"][0]
        self.assertEqual("record.escalation.applied", entry["DetailType"])
        detail = json.loads(entry["Detail"])
        self.assertEqual("ENC-ESC-001", detail["escalation_id"])
        self.assertEqual("io@jreese.net", detail["approved_by"])

    def test_escalation_fsm_helper_refuses_illegal_edges(self):
        with self.assertRaises(ValueError):
            self.lf._escalation_fsm_transition(
                "enceladus", "ENC-ESC-001", "requested", "applied", "system")


class TestDeployArcChangeApply(_ApplierBase):
    def test_arc_rewrite_preserves_active_checkout(self):
        ddb = _FakeDdb(escalation=_escalation_item(), target=_target_task(checked_out=True))
        resp = self._apply(ddb)
        self.assertEqual(200, resp["statusCode"])
        target_update = ddb.target_updates()[0]
        expression = target_update["UpdateExpression"]
        self.assertEqual("transition_type",
                         target_update["ExpressionAttributeNames"]["#tt"])
        self.assertEqual({"S": "code_only"},
                         target_update["ExpressionAttributeValues"][":arc"])
        # checkout_transition_type recomputed alongside the arc...
        self.assertIn("checkout_transition_type = :arc", expression)
        # ...while checkout ownership fields are untouched (checkout survives).
        for forbidden in ("checked_out_by", "checkout_state", "checked_out_at",
                          "active_agent_session_id"):
            self.assertNotIn(forbidden, expression)

    def test_arc_rewrite_without_checkout_snapshot_skips_mirror(self):
        ddb = _FakeDdb(escalation=_escalation_item(),
                       target=_target_task(checked_out=False))
        self._apply(ddb)
        expression = ddb.target_updates()[0]["UpdateExpression"]
        self.assertNotIn("checkout_transition_type", expression)

    def test_provenance_rides_the_same_atomic_write(self):
        ddb = _FakeDdb(escalation=_escalation_item(), target=_target_task())
        self._apply(ddb)
        target_update = ddb.target_updates()[0]
        expression = target_update["UpdateExpression"]
        self.assertIn("escalation_provenance = list_append", expression)
        self.assertIn("history = list_append", expression)
        history_entry = target_update["ExpressionAttributeValues"][":hentry"]["L"][0]["M"]
        note = history_entry["description"]["S"]
        self.assertIn("[ESCALATION-APPLIED] ENC-ESC-001", note)
        self.assertIn("requested_by=ENC-SES-02F", note)
        self.assertIn("approved_by=io@jreese.net", note)
        self.assertIn("before=", note)
        self.assertIn("after=", note)
        provenance = target_update["ExpressionAttributeValues"][":esc"]["L"]
        self.assertEqual([{"S": "ENC-ESC-001"}], provenance)


def _override_escalation(target_status, field_values=None, target="ENC-TSK-J10"):
    payload = {"target_status": target_status}
    if field_values is not None:
        payload["field_values"] = field_values
    return _escalation_item(mutation_type="direct_state_override",
                            payload=payload, target=target)


class TestDirectStateOverrideApply(_ApplierBase):
    def test_coding_complete_to_closed_waives_and_flags_closure(self):
        ddb = _FakeDdb(
            escalation=_override_escalation("closed"),
            target=_target_task(status="coding-complete", checked_out=False))
        resp = self._apply(ddb)
        self.assertEqual(200, resp["statusCode"])
        result = json.loads(resp["body"])["result"]
        self.assertEqual(["live_validation_evidence"], result["waived_fields"])
        target_update = ddb.target_updates()[0]
        expression = target_update["UpdateExpression"]
        values = target_update["ExpressionAttributeValues"]
        names = target_update["ExpressionAttributeNames"]
        self.assertEqual({"S": "closed"}, values[":target_status"])
        self.assertEqual("live_validation_evidence", names["#wv0"])
        sentinel = values[":wv0"]["M"]
        self.assertTrue(sentinel["escalation_waived"]["BOOL"])
        self.assertEqual("ENC-ESC-001", sentinel["escalation_id"]["S"])
        self.assertIn("waived_at", sentinel)
        self.assertIn("escalated_closure = :esc_closure", expression)
        self.assertTrue(values[":esc_closure"]["BOOL"])
        self.assertIn("ADD closed_count :one_count", expression)

    def test_closed_to_pr_path_illegal_transition_lands(self):
        ddb = _FakeDdb(
            escalation=_override_escalation("pr"),
            target=_target_task(status="closed", checked_out=False))
        resp = self._apply(ddb)
        self.assertEqual(200, resp["statusCode"])
        target_update = ddb.target_updates()[0]
        values = target_update["ExpressionAttributeValues"]
        self.assertEqual({"S": "pr"}, values[":target_status"])
        expression = target_update["UpdateExpression"]
        self.assertNotIn("escalated_closure", expression)
        self.assertNotIn("closed_count", expression)
        self.assertNotIn("#wv0", expression)

    def test_supplied_field_values_written_verbatim_not_waived(self):
        ddb = _FakeDdb(
            escalation=_override_escalation(
                "closed", {"live_validation_evidence": "gamma smoke 200 OK"}),
            target=_target_task(status="deploy-success", checked_out=False))
        resp = self._apply(ddb)
        result = json.loads(resp["body"])["result"]
        self.assertEqual([], result["waived_fields"])
        target_update = ddb.target_updates()[0]
        names = target_update["ExpressionAttributeNames"]
        values = target_update["ExpressionAttributeValues"]
        self.assertEqual("live_validation_evidence", names["#fv0"])
        self.assertEqual({"S": "gamma smoke 200 OK"}, values[":fv0"])

    def test_deploy_success_waives_arc_specific_evidence_key(self):
        ddb = _FakeDdb(
            escalation=_override_escalation("deploy-success"),
            target=_target_task(status="pr", transition_type="web_deploy",
                                checked_out=False))
        self._apply(ddb)
        names = ddb.target_updates()[0]["ExpressionAttributeNames"]
        self.assertEqual("web_deploy_evidence", names["#wv0"])

    def test_issue_closure_waives_evidence_without_closed_count(self):
        issue = {
            "project_id": {"S": "enceladus"},
            "record_id": {"S": "issue#ENC-ISS-441"},
            "item_id": {"S": "ENC-ISS-441"},
            "record_type": {"S": "issue"},
            "status": {"S": "open"},
        }
        ddb = _FakeDdb(
            escalation=_override_escalation("closed", target="ENC-ISS-441"),
            target=issue)
        resp = self._apply(ddb)
        self.assertEqual(200, resp["statusCode"])
        target_update = ddb.target_updates()[0]
        expression = target_update["UpdateExpression"]
        self.assertEqual("evidence",
                         target_update["ExpressionAttributeNames"]["#wv0"])
        self.assertIn("escalated_closure", expression)
        self.assertNotIn("closed_count", expression)

    def test_works_on_closed_record_with_no_checkout(self):
        ddb = _FakeDdb(
            escalation=_override_escalation(
                "deploy-success", {"deploy_evidence": {"id": 1, "conclusion": "success"}}),
            target=_target_task(status="closed", checked_out=False))
        resp = self._apply(ddb)
        self.assertEqual(200, resp["statusCode"])
        self.assertEqual(1, len(ddb.target_updates()))


class TestValidatorsUntouched(unittest.TestCase):
    """AC-7: the normal FSM acquired no bypass — the applier is a separate path."""

    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_normal_task_fsm_still_forbids_the_overridden_paths(self):
        graph = self.lf._VALID_TRANSITIONS["task"]
        self.assertNotIn("closed", graph)  # closed is terminal — no forward edges
        self.assertNotIn("closed", graph["coding-complete"])  # no direct jump

    def test_update_field_signature_carries_no_bypass_parameter(self):
        import inspect
        params = set(inspect.signature(self.lf._handle_update_field).parameters)
        self.assertFalse(
            {"escalation", "bypass", "override", "skip_validation"} & params,
            "validator entry point must not grow bypass parameters")

    def test_revert_transitions_unchanged(self):
        self.assertEqual({"in-progress": {"open"}},
                         self.lf._REVERT_TRANSITIONS["issue"])

    def test_escalation_fsm_is_not_wired_into_normal_transitions(self):
        for record_type_graph in self.lf._VALID_TRANSITIONS.values():
            for status in record_type_graph:
                self.assertNotIn(status, self.lf._ESCALATION_FSM.keys() - set())


class TestApplyRouteRegex(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_apply_sub_path_matches(self):
        match = self.lf._RE_ESCALATION.match(
            "/api/v1/tracker/enceladus/escalation/ENC-ESC-001/apply")
        self.assertIsNotNone(match)
        self.assertEqual("ENC-ESC-001", match.group("id"))
        self.assertEqual("apply", match.group("sub"))

    def test_list_pseudo_id_matches_as_id(self):
        match = self.lf._RE_ESCALATION.match("/enceladus/escalation/list")
        self.assertIsNotNone(match)
        self.assertEqual("list", match.group("id"))
        self.assertIsNone(match.group("sub"))

    def test_arbitrary_sub_does_not_match(self):
        self.assertIsNone(self.lf._RE_ESCALATION.match(
            "/enceladus/escalation/ENC-ESC-001/delete"))


if __name__ == "__main__":
    unittest.main()
