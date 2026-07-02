"""ENC-TSK-J68 (ENC-FTR-121 Ph1): Escalations entity + request/read surface tests.

Covers, in the established tracker_mutation house style (no DDB round-trip):
the mutation-handler registry validate_payload contracts (deploy_arc_change
arc-type legality + task-only targets; direct_state_override status legality
with path legality DELIBERATELY unchecked — that is what io approval
overrides), the request handler's fail-fast envelope validation (malformed
requests write NOTHING), server-side ENC-ESC minting through the existing
atomic-counter ID authority, the `requested` event append shape (§11.2),
get/list read paths with status/target/session filters, and the route regex.

The applier (applyEscalatedMutation), waiver sentinels, and escalated_closure
land in Ph2 (ENC-TSK-J69) with their own test weight.
"""
import json
import unittest
from unittest import mock


def _fake_ddb(target_item=None, counter_next=7):
    """MagicMock DDB serving the target read, the mint counter, and put capture.

    get_item routes on the record_id key: counter#escalation returns a live
    counter (so _next_record_id skips the seed scan); anything else returns
    target_item (or nothing).
    """
    fake = mock.MagicMock()

    def _get_item(TableName=None, Key=None, **kwargs):
        record_id = (Key or {}).get("record_id", {}).get("S", "")
        if record_id.startswith("counter#"):
            return {"Item": {"next_num": {"N": str(counter_next - 1)}}}
        if target_item is not None:
            return {"Item": target_item}
        return {}

    fake.get_item.side_effect = _get_item
    fake.update_item.return_value = {"Attributes": {"next_num": {"N": str(counter_next)}}}
    return fake


def _request_body(**overrides):
    body = {
        "target_record_id": "ENC-TSK-J10",
        "mutation_type": "deploy_arc_change",
        "payload": {"new_deploy_arc_type": "code_only"},
        "justification": "Arc misclassified at create; task ships no deployable artifact.",
        "requested_by": {"session_id": "ENC-SES-02F", "agent_type_id": "ENC-AGT-006"},
    }
    body.update(overrides)
    return body


_TARGET_TASK_ITEM = {
    "project_id": {"S": "enceladus"},
    "record_id": {"S": "task#ENC-TSK-J10"},
    "item_id": {"S": "ENC-TSK-J10"},
    "record_type": {"S": "task"},
    "status": {"S": "open"},
    "title": {"S": "target"},
}


class TestStatusUniverse(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_task_universe_includes_full_arc_and_superseded(self):
        statuses = self.lf._statuses_for_record_type("task")
        for expected in ("open", "in-progress", "coding-complete", "committed",
                         "pr", "merged-main", "deploy-init", "deploy-success",
                         "closed", "coding-updates", "superseded"):
            self.assertIn(expected, statuses)

    def test_issue_universe(self):
        statuses = self.lf._statuses_for_record_type("issue")
        self.assertEqual({"open", "in-progress", "closed", "superseded"}, statuses)

    def test_feature_universe_has_no_superseded(self):
        statuses = self.lf._statuses_for_record_type("feature")
        self.assertIn("production", statuses)
        self.assertNotIn("superseded", statuses)


class TestDeployArcChangeValidation(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.validate = lf._ESCALATION_MUTATION_HANDLERS["deploy_arc_change"]["validate_payload"]

    def test_legal_arc_on_task_passes(self):
        self.assertEqual("", self.validate({"new_deploy_arc_type": "code_only"}, "task"))

    def test_non_task_target_rejected(self):
        err = self.validate({"new_deploy_arc_type": "code_only"}, "issue")
        self.assertIn("task records", err)

    def test_missing_arc_rejected(self):
        self.assertIn("new_deploy_arc_type", self.validate({}, "task"))

    def test_illegal_arc_rejected(self):
        err = self.validate({"new_deploy_arc_type": "carrier_pigeon"}, "task")
        self.assertIn("carrier_pigeon", err)
        self.assertIn("github_pr_deploy", err)


class TestDirectStateOverrideValidation(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.validate = lf._ESCALATION_MUTATION_HANDLERS["direct_state_override"]["validate_payload"]

    def test_path_illegal_but_dictionary_legal_status_passes(self):
        # closed -> pr is path-illegal in the normal FSM; the validator must
        # accept it (status legality only) — path is what io approval overrides.
        self.assertEqual("", self.validate({"target_status": "pr"}, "task"))

    def test_terminal_closure_status_passes(self):
        self.assertEqual("", self.validate({"target_status": "closed"}, "task"))

    def test_superseded_passes_for_task(self):
        self.assertEqual("", self.validate({"target_status": "superseded"}, "task"))

    def test_status_from_wrong_type_universe_rejected(self):
        err = self.validate({"target_status": "deploy-success"}, "issue")
        self.assertIn("deploy-success", err)

    def test_missing_target_status_rejected(self):
        self.assertIn("target_status", self.validate({}, "task"))

    def test_non_dict_field_values_rejected(self):
        err = self.validate({"target_status": "closed", "field_values": "oops"}, "task")
        self.assertIn("field_values", err)

    def test_dict_field_values_passes(self):
        payload = {"target_status": "closed", "field_values": {"live_validation_evidence": "gamma smoke ok"}}
        self.assertEqual("", self.validate(payload, "task"))


class TestTargetParse(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_task_issue_feature_targets_resolve(self):
        for record_id, expected_type in (("ENC-TSK-J10", "task"), ("ENC-ISS-441", "issue"), ("ENC-FTR-121", "feature")):
            record_type, sort_key, err = self.lf._parse_escalation_target(record_id)
            self.assertEqual("", err)
            self.assertEqual(expected_type, record_type)
            self.assertEqual(f"{expected_type}#{record_id}", sort_key)

    def test_lesson_target_rejected(self):
        _, _, err = self.lf._parse_escalation_target("ENC-LSN-039")
        self.assertIn("not escalatable", err)

    def test_malformed_id_rejected(self):
        _, _, err = self.lf._parse_escalation_target("garbage")
        self.assertIn("PREFIX-SEG-SEQ", err)


class TestEscalationRequest(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf
        self._flag = mock.patch.object(lf, "ENABLE_ESCALATION_PRIMITIVE", True)
        self._flag.start()

    def tearDown(self):
        self._flag.stop()

    def _run(self, body, ddb):
        with mock.patch.object(self.lf, "_get_ddb", return_value=ddb), \
             mock.patch.object(self.lf, "_get_project_prefix", return_value="ENC"):
            return self.lf._handle_escalation_request("enceladus", body)

    def test_happy_path_mints_and_writes_requested_item(self):
        ddb = _fake_ddb(target_item=_TARGET_TASK_ITEM, counter_next=7)
        resp = self._run(_request_body(), ddb)
        self.assertEqual(201, resp["statusCode"])
        payload = json.loads(resp["body"])
        self.assertTrue(payload["success"])
        self.assertEqual("requested", payload["status"])
        self.assertRegex(payload["escalation_id"], r"^ENC-ESC-[A-Z0-9]{3}$")

        self.assertEqual(1, ddb.put_item.call_count)
        item = ddb.put_item.call_args.kwargs["Item"]
        self.assertEqual(f"escalation#{payload['escalation_id']}", item["record_id"]["S"])
        self.assertEqual("escalation", item["record_type"]["S"])
        self.assertEqual("requested", item["status"]["S"])
        self.assertEqual("ENC-SES-02F", item["requested_by"]["M"]["session_id"]["S"])
        self.assertFalse(item["requested_by"]["M"]["sci_present"]["BOOL"])
        events = item["events"]["L"]
        self.assertEqual(1, len(events))
        self.assertEqual("requested", events[0]["M"]["event_type"]["S"])
        self.assertEqual("ENC-SES-02F", events[0]["M"]["actor"]["S"])
        stored_payload = json.loads(item["payload"]["S"])
        self.assertEqual("code_only", stored_payload["new_deploy_arc_type"])

    def test_expected_version_persisted_when_supplied(self):
        ddb = _fake_ddb(target_item=_TARGET_TASK_ITEM)
        resp = self._run(_request_body(expected_version="sync_version:4"), ddb)
        self.assertEqual(201, resp["statusCode"])
        item = ddb.put_item.call_args.kwargs["Item"]
        self.assertEqual("sync_version:4", item["expected_version"]["S"])

    def test_session_falls_back_to_write_source_provider(self):
        ddb = _fake_ddb(target_item=_TARGET_TASK_ITEM)
        body = _request_body(requested_by=None,
                             write_source={"provider": "ENC-SES-02F", "channel": "mcp_server"})
        resp = self._run(body, ddb)
        self.assertEqual(201, resp["statusCode"])
        item = ddb.put_item.call_args.kwargs["Item"]
        self.assertEqual("ENC-SES-02F", item["requested_by"]["M"]["session_id"]["S"])

    def _assert_rejected_without_write(self, body, status, fragment, target_item=_TARGET_TASK_ITEM):
        ddb = _fake_ddb(target_item=target_item)
        resp = self._run(body, ddb)
        self.assertEqual(status, resp["statusCode"])
        self.assertIn(fragment, json.loads(resp["body"])["error"])
        ddb.put_item.assert_not_called()

    def test_unknown_mutation_type_rejected_without_write(self):
        self._assert_rejected_without_write(
            _request_body(mutation_type="delete_everything"), 400, "delete_everything")

    def test_missing_justification_rejected_without_write(self):
        self._assert_rejected_without_write(
            _request_body(justification=""), 400, "justification")

    def test_missing_payload_rejected_without_write(self):
        self._assert_rejected_without_write(
            _request_body(payload=None), 400, "payload")

    def test_missing_target_rejected_without_write(self):
        self._assert_rejected_without_write(
            _request_body(target_record_id=""), 400, "target_record_id")

    def test_missing_session_rejected_without_write(self):
        self._assert_rejected_without_write(
            _request_body(requested_by={}), 400, "session_id")

    def test_invalid_payload_for_handler_rejected_without_write(self):
        self._assert_rejected_without_write(
            _request_body(payload={"new_deploy_arc_type": "bogus"}), 400, "bogus")

    def test_nonexistent_target_rejected_without_write(self):
        self._assert_rejected_without_write(
            _request_body(), 404, "not found", target_item=None)

    def test_arc_change_on_issue_target_rejected_without_write(self):
        body = _request_body(target_record_id="ENC-ISS-441")
        self._assert_rejected_without_write(body, 400, "task records")

    def test_flag_off_returns_503(self):
        ddb = _fake_ddb(target_item=_TARGET_TASK_ITEM)
        with mock.patch.object(self.lf, "ENABLE_ESCALATION_PRIMITIVE", False):
            resp = self._run(_request_body(), ddb)
        self.assertEqual(503, resp["statusCode"])
        ddb.put_item.assert_not_called()


class TestEscalationGet(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf
        self._flag = mock.patch.object(lf, "ENABLE_ESCALATION_PRIMITIVE", True)
        self._flag.start()

    def tearDown(self):
        self._flag.stop()

    def test_found_returns_deserialized_escalation_with_parsed_payload(self):
        item = {
            "project_id": {"S": "enceladus"},
            "record_id": {"S": "escalation#ENC-ESC-001"},
            "item_id": {"S": "ENC-ESC-001"},
            "record_type": {"S": "escalation"},
            "status": {"S": "requested"},
            "payload": {"S": json.dumps({"target_status": "closed"})},
            "events": {"L": [{"M": {
                "event_type": {"S": "requested"},
                "at": {"S": "2026-07-02T04:00:00Z"},
                "actor": {"S": "ENC-SES-02F"},
                "detail": {"S": json.dumps({"mutation_type": "direct_state_override"})},
            }}]},
        }
        fake = mock.MagicMock()
        fake.get_item.return_value = {"Item": item}
        with mock.patch.object(self.lf, "_get_ddb", return_value=fake):
            resp = self.lf._handle_escalation_get("enceladus", "ENC-ESC-001")
        self.assertEqual(200, resp["statusCode"])
        escalation = json.loads(resp["body"])["escalation"]
        self.assertEqual({"target_status": "closed"}, escalation["payload"])
        self.assertEqual("direct_state_override", escalation["events"][0]["detail"]["mutation_type"])
        key = fake.get_item.call_args.kwargs["Key"]
        self.assertEqual("escalation#ENC-ESC-001", key["record_id"]["S"])

    def test_missing_returns_404(self):
        fake = mock.MagicMock()
        fake.get_item.return_value = {}
        with mock.patch.object(self.lf, "_get_ddb", return_value=fake):
            resp = self.lf._handle_escalation_get("enceladus", "ENC-ESC-999")
        self.assertEqual(404, resp["statusCode"])


class TestEscalationList(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf
        self._flag = mock.patch.object(lf, "ENABLE_ESCALATION_PRIMITIVE", True)
        self._flag.start()

    def tearDown(self):
        self._flag.stop()

    def _item(self, esc_id, created_at):
        return {
            "project_id": {"S": "enceladus"},
            "record_id": {"S": f"escalation#{esc_id}"},
            "item_id": {"S": esc_id},
            "record_type": {"S": "escalation"},
            "status": {"S": "requested"},
            "payload": {"S": "{}"},
            "created_at": {"S": created_at},
        }

    def _run(self, query_params, items):
        fake = mock.MagicMock()
        fake.query.return_value = {"Items": items}
        with mock.patch.object(self.lf, "_get_ddb", return_value=fake):
            resp = self.lf._handle_escalation_list("enceladus", query_params)
        return resp, fake

    def test_unfiltered_list_sorts_newest_first(self):
        items = [self._item("ENC-ESC-001", "2026-07-02T01:00:00Z"),
                 self._item("ENC-ESC-002", "2026-07-02T03:00:00Z")]
        resp, fake = self._run({}, items)
        self.assertEqual(200, resp["statusCode"])
        body = json.loads(resp["body"])
        self.assertEqual(2, body["count"])
        self.assertEqual("ENC-ESC-002", body["escalations"][0]["item_id"])
        kwargs = fake.query.call_args.kwargs
        self.assertIn("begins_with(record_id, :esc_prefix)", kwargs["KeyConditionExpression"])
        self.assertNotIn("FilterExpression", kwargs)

    def test_status_filter_lands_in_filter_expression(self):
        resp, fake = self._run({"status": "requested"}, [])
        self.assertEqual(200, resp["statusCode"])
        kwargs = fake.query.call_args.kwargs
        self.assertIn("#st = :status_filter", kwargs["FilterExpression"])
        self.assertEqual({"#st": "status"}, kwargs["ExpressionAttributeNames"])
        self.assertEqual({"S": "requested"}, kwargs["ExpressionAttributeValues"][":status_filter"])

    def test_target_and_session_filters_compose(self):
        resp, fake = self._run(
            {"target_record_id": "ENC-TSK-J10", "session_id": "ENC-SES-02F"}, [])
        kwargs = fake.query.call_args.kwargs
        self.assertIn("target_record_id = :target_filter", kwargs["FilterExpression"])
        self.assertIn("requested_by.session_id = :session_filter", kwargs["FilterExpression"])
        self.assertIn(" AND ", kwargs["FilterExpression"])

    def test_invalid_status_filter_rejected(self):
        resp, fake = self._run({"status": "pending"}, [])
        self.assertEqual(400, resp["statusCode"])
        fake.query.assert_not_called()

    def test_page_size_clamped(self):
        items = [self._item(f"ENC-ESC-{i:03d}", f"2026-07-02T0{i}:00:00Z") for i in range(1, 4)]
        resp, _ = self._run({"page_size": "2"}, items)
        body = json.loads(resp["body"])
        self.assertEqual(2, body["count"])


class TestEscalationRoute(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_regex_matches_collection_and_item_paths(self):
        for path, expected_id in (
            ("/api/v1/tracker/enceladus/escalation", None),
            ("/enceladus/escalation", None),
            ("/api/v1/tracker/enceladus/escalation/ENC-ESC-001", "ENC-ESC-001"),
        ):
            match = self.lf._RE_ESCALATION.match(path)
            self.assertIsNotNone(match, path)
            self.assertEqual("enceladus", match.group("project"))
            self.assertEqual(expected_id, match.group("id"))

    def test_regex_does_not_swallow_other_routes(self):
        self.assertIsNone(self.lf._RE_ESCALATION.match("/enceladus/task"))
        self.assertIsNone(self.lf._RE_ESCALATION.match("/enceladus/task/ENC-TSK-J10"))

    def test_escalation_never_joined_generic_record_types(self):
        # Guard: escalations must stay OUT of the generic CRUD surface.
        self.assertNotIn("escalation", self.lf._RECORD_TYPES)
        self.assertEqual("ESC", self.lf._TRACKER_TYPE_SUFFIX["escalation"])
        self.assertEqual("escalation", self.lf._ID_SEGMENT_TO_TYPE["ESC"])


if __name__ == "__main__":
    unittest.main()
