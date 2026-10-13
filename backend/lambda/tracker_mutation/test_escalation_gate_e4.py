"""ENC-TSK-967 (DVP-PLN-013 E4-W1.2, phase 1): gate-generalised escalation entity.

Covers the F-10 default expiry for every decision kind, request-field validation,
read-time backfill of legacy ESC records (no migration, additive only -- D9),
the cross-project list with state/kind filters (ENC-ISS-773 at the API),
fail-closed expiry on apply, and the expiry sweeper.
"""
import datetime as dt
import json
import os
import unittest
from unittest import mock

from test_escalation_applier_j69 import _FakeDdb, _escalation_item, _target_task
from test_escalation_j68 import _TARGET_TASK_ITEM, _fake_ddb, _request_body

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 10, 11, 12, 0, 0, tzinfo=UTC)

# kind -> (ttl, onExpire)
F10 = {
    "acceptance": (dt.timedelta(days=7), "regenerate"),
    "reconciliation": (dt.timedelta(days=7), "regenerate"),
    "stale_lock": (dt.timedelta(days=7), "regenerate"),
    "escalation": (dt.timedelta(hours=72), "deny"),
    "tool_call": (dt.timedelta(hours=72), "deny"),
    "security": (dt.timedelta(hours=72), "deny"),
    "limit": (dt.timedelta(hours=24), "deny"),
}


def _z(ts):
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


class _Base(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf
        self._patches = [
            mock.patch.object(lf, "ENABLE_ESCALATION_PRIMITIVE", True),
            mock.patch.dict(os.environ, {"GATE_PRODUCER_PRINCIPALS": json.dumps({"think": ["think"]})}),
            mock.patch.object(lf, "_gate_now", return_value=NOW),
            mock.patch.object(lf, "_get_events", return_value=mock.MagicMock()),
        ]
        for patch in self._patches:
            patch.start()

    def tearDown(self):
        for patch in self._patches:
            patch.stop()

    def _request(self, body, ddb=None):
        ddb = ddb or _fake_ddb(target_item=_TARGET_TASK_ITEM)
        with mock.patch.object(self.lf, "_get_ddb", return_value=ddb), \
             mock.patch.object(self.lf, "_get_project_prefix", return_value="ENC"):
            resp = self.lf._handle_escalation_request("enceladus", body)
        return resp, ddb


class TestF10Defaults(_Base):
    def test_every_decision_kind_gets_its_f10_ttl_and_on_expire(self):
        for kind, (ttl, on_expire) in F10.items():
            with self.subTest(kind=kind):
                resp, ddb = self._request(_request_body(kind=kind))
                self.assertEqual(201, resp["statusCode"], resp["body"])
                body = json.loads(resp["body"])
                self.assertEqual(kind, body["kind"])
                self.assertEqual("decision", body["family"])
                self.assertEqual(_z(NOW + ttl), body["expiresAt"])
                self.assertEqual(on_expire, body["onExpire"])
                self.assertEqual("pending", body["state"])
                item = ddb.put_item.call_args.kwargs["Item"]
                self.assertEqual(_z(NOW + ttl), item["expiresAt"]["S"])
                self.assertEqual(kind, item["kind"]["S"])

    def test_default_risk_per_kind(self):
        expect = {"escalation": "high", "security": "critical", "limit": "medium",
                  "stale_lock": "low", "acceptance": "medium"}
        for kind, risk in expect.items():
            with self.subTest(kind=kind):
                resp, _ = self._request(_request_body(kind=kind))
                self.assertEqual(risk, json.loads(resp["body"])["risk"])

    def test_legacy_request_without_gate_fields_is_kind_escalation_72h_deny(self):
        resp, ddb = self._request(_request_body())
        body = json.loads(resp["body"])
        self.assertEqual("escalation", body["kind"])
        self.assertEqual(_z(NOW + dt.timedelta(hours=72)), body["expiresAt"])
        self.assertEqual("deny", body["onExpire"])
        # D9: every pre-existing response key is still present, unchanged.
        for key in ("success", "escalation_id", "status", "target_record_id",
                    "target_record_type", "mutation_type", "created_at"):
            self.assertIn(key, body)
        self.assertEqual("requested", body["status"])

    def test_explicit_valid_fields_are_stored_verbatim(self):
        cands = [{"id": "c1", "label": "raise limit"}, {"id": "c2", "label": "pause actor"}]
        ev = [{"label": "metric", "ref": "cw://x", "excerpt": "95%"}]
        blast = {"records": 3, "stacks": ["enceladus"], "irreversible": False}
        exp = _z(NOW + dt.timedelta(hours=5))
        resp, ddb = self._request(_request_body(
            kind="limit", risk="critical", expiresAt=exp, onExpire="deny",
            candidates=cands, evidence=ev, blastRadius=blast,
            snoozedUntil=_z(NOW + dt.timedelta(hours=2)), title="Budget breach",
            source_principal="think"))
        self.assertEqual(201, resp["statusCode"], resp["body"])
        item = ddb.put_item.call_args.kwargs["Item"]
        self.assertEqual(exp, item["expiresAt"]["S"])
        self.assertEqual("critical", item["risk"]["S"])
        self.assertEqual(cands, json.loads(item["candidates"]["S"]))
        self.assertEqual(blast, json.loads(item["blastRadius"]["S"]))
        self.assertEqual("think", item["sourcePrincipal"]["S"])
        self.assertEqual("snoozed", json.loads(resp["body"])["state"])


class TestRequestValidation(_Base):
    def _bad(self, **fields):
        resp, ddb = self._request(_request_body(**fields))
        self.assertEqual(400, resp["statusCode"], resp["body"])
        self.assertEqual(0, ddb.put_item.call_count)  # nothing written
        return json.loads(resp["body"])["error"]

    def test_unknown_kind(self):
        self.assertIn("Invalid kind", self._bad(kind="gate"))

    def test_telemetry_kind_refused(self):
        self.assertIn("Telemetry", self._bad(kind="drift"))

    def test_family_contradicting_kind(self):
        self.assertIn("contradicts", self._bad(kind="limit", family="telemetry"))

    def test_invalid_risk_and_on_expire(self):
        self._bad(risk="severe")
        self._bad(onExpire="auto_clear")

    def test_expiry_past_and_over_30d_refused(self):
        self.assertIn("past", self._bad(expiresAt=_z(NOW - dt.timedelta(minutes=1))))
        self.assertIn("30d", self._bad(expiresAt=_z(NOW + dt.timedelta(days=31))))
        self.assertIn("ISO", self._bad(expiresAt="soon"))

    def test_30d_exactly_is_accepted(self):
        resp, _ = self._request(_request_body(expiresAt=_z(NOW + dt.timedelta(days=30))))
        self.assertEqual(201, resp["statusCode"])

    def test_snooze_cannot_extend_past_expiry(self):
        self.assertIn("snoozedUntil", self._bad(
            expiresAt=_z(NOW + dt.timedelta(hours=1)),
            snoozedUntil=_z(NOW + dt.timedelta(hours=2))))

    def test_candidate_shape(self):
        self._bad(candidates=[])
        self._bad(candidates=[{"id": "a"}])
        self._bad(candidates=[{"id": "a", "label": "x"}, {"id": "a", "label": "y"}])

    def test_evidence_and_blast_shape(self):
        self._bad(evidence=[{"label": "x"}])
        self._bad(blastRadius={"records": 1})
        self._bad(blastRadius={"records": True, "stacks": [], "irreversible": False})


class TestLegacyBackfillOnRead(_Base):
    def test_legacy_record_reads_as_escalation_with_72h_expiry(self):
        raw = _escalation_item(status="requested")  # created 2026-07-02T04:00:00Z
        with mock.patch.object(self.lf, "_gate_now",
                               return_value=dt.datetime(2026, 7, 2, 5, 0, tzinfo=UTC)):
            rec = self.lf._escalation_public(raw)
        self.assertEqual("escalation", rec["kind"])
        self.assertEqual("decision", rec["family"])
        self.assertEqual("high", rec["risk"])
        self.assertEqual("deny", rec["onExpire"])
        self.assertEqual("2026-07-05T04:00:00Z", rec["expiresAt"])
        self.assertEqual("pending", rec["state"])
        self.assertEqual("ENC-TSK-J10", rec["subject"]["record_id"])
        self.assertEqual("ENC-SES-02F", rec["requestedBy"])
        self.assertEqual([{"label": "target", "ref": "ENC-TSK-J10"}], rec["evidence"])
        for name in ("kind", "family", "risk", "onExpire", "expiresAt"):
            self.assertIn(name, rec["gateBackfilled"])
        # additive: legacy fields untouched
        self.assertEqual("requested", rec["status"])
        self.assertEqual({"new_deploy_arc_type": "code_only"}, rec["payload"])

    def test_legacy_requested_past_72h_reads_expired_and_decided_reads_decided(self):
        late = dt.datetime(2026, 7, 5, 4, 0, 0, tzinfo=UTC)  # exactly created+72h
        with mock.patch.object(self.lf, "_gate_now", return_value=late):
            self.assertEqual("expired", self.lf._escalation_public(_escalation_item(status="requested"))["state"])
            self.assertEqual("decided", self.lf._escalation_public(_escalation_item(status="approved"))["state"])
            self.assertEqual("decided", self.lf._escalation_public(_escalation_item(status="denied"))["state"])

    def test_one_second_before_expiry_is_still_pending(self):
        t = dt.datetime(2026, 7, 5, 3, 59, 59, tzinfo=UTC)
        with mock.patch.object(self.lf, "_gate_now", return_value=t):
            self.assertEqual("pending", self.lf._escalation_public(_escalation_item(status="requested"))["state"])

    def test_stored_values_win_and_json_string_attrs_parse(self):
        raw = _escalation_item(status="requested")
        raw["kind"] = {"S": "limit"}
        raw["expiresAt"] = {"S": "2026-07-02T10:00:00Z"}
        raw["onExpire"] = {"S": "deny"}
        raw["candidates"] = {"S": json.dumps([{"id": "c1", "label": "x"}])}
        with mock.patch.object(self.lf, "_gate_now",
                               return_value=dt.datetime(2026, 7, 2, 5, 0, tzinfo=UTC)):
            rec = self.lf._escalation_public(raw)
        self.assertEqual("limit", rec["kind"])
        self.assertEqual("2026-07-02T10:00:00Z", rec["expiresAt"])
        self.assertEqual([{"id": "c1", "label": "x"}], rec["candidates"])
        self.assertNotIn("expiresAt", rec.get("gateBackfilled", []))

    def test_regenerate_kind_reads_superseded_when_expired(self):
        raw = _escalation_item(status="requested")
        raw["kind"] = {"S": "stale_lock"}
        late = dt.datetime(2026, 7, 9, 4, 0, 0, tzinfo=UTC)  # created + 7d
        with mock.patch.object(self.lf, "_gate_now", return_value=late):
            self.assertEqual("superseded", self.lf._escalation_public(raw)["state"])

    def test_snoozed_state(self):
        raw = _escalation_item(status="requested")
        raw["snoozedUntil"] = {"S": "2026-07-02T08:00:00Z"}
        with mock.patch.object(self.lf, "_gate_now",
                               return_value=dt.datetime(2026, 7, 2, 5, 0, tzinfo=UTC)):
            self.assertEqual("snoozed", self.lf._escalation_public(raw)["state"])

    def test_unparsable_stored_expiry_fails_closed(self):
        raw = _escalation_item(status="requested")
        raw["expiresAt"] = {"S": "garbage"}
        exp = self.lf._escalation_expiry({"kind": "escalation", "expiresAt": "garbage",
                                           "created_at": "2026-07-02T04:00:00Z"}, NOW)
        # a garbage stored value falls back to the default window derived from
        # created_at (long past) -> expired, never silently open
        self.assertTrue(exp["expired"])
        no_clock = self.lf._escalation_expiry({"kind": "escalation", "created_at": "?"}, NOW)
        self.assertTrue(no_clock["expired"])


class TestCrossProjectList(_Base):
    def _item(self, project, esc_id, created_at, status="requested", kind=None):
        item = {
            "project_id": {"S": project}, "record_id": {"S": f"escalation#{esc_id}"},
            "item_id": {"S": esc_id}, "record_type": {"S": "escalation"},
            "status": {"S": status}, "payload": {"S": "{}"}, "created_at": {"S": created_at},
        }
        if kind:
            item["kind"] = {"S": kind}
        return item

    def _ddb(self):
        fake = mock.MagicMock()
        fake.scan.return_value = {"Items": [
            {"project_id": {"S": "enceladus"}}, {"project_id": {"S": "devops"}}]}
        data = {
            "enceladus": [self._item("enceladus", "ENC-ESC-001", "2026-10-10T01:00:00Z")],
            "devops": [
                self._item("devops", "DVP-ESC-001", "2026-10-11T01:00:00Z", kind="tool_call"),
                self._item("devops", "DVP-ESC-002", "2026-10-11T02:00:00Z", status="approved"),
                self._item("devops", "DVP-ESC-003", "2026-09-01T02:00:00Z"),  # long expired
            ],
        }

        def _query(**kwargs):
            pid = kwargs["ExpressionAttributeValues"][":pid"]["S"]
            return {"Items": list(data[pid])}

        fake.query.side_effect = _query
        return fake

    def _list(self, project, params):
        with mock.patch.object(self.lf, "_get_ddb", return_value=self._ddb()):
            resp = self.lf._handle_escalation_list(project, params)
        return resp

    def test_star_project_lists_every_kind_across_projects(self):
        resp = self._list("*", {})
        self.assertEqual(200, resp["statusCode"])
        body = json.loads(resp["body"])
        ids = [e["item_id"] for e in body["escalations"]]
        self.assertEqual(["DVP-ESC-002", "DVP-ESC-001", "ENC-ESC-001", "DVP-ESC-003"], ids)
        self.assertEqual({"enceladus", "devops"}, {e["project_id"] for e in body["escalations"]})
        self.assertEqual("all_projects", body["scope"])
        self.assertEqual(2, body["projects_scanned"])
        self.assertEqual({"escalation", "tool_call"}, {e["kind"] for e in body["escalations"]})

    def test_underscore_sentinel_and_all_projects_param(self):
        self.assertEqual(4, json.loads(self._list("_", {})["body"])["count"])
        self.assertEqual(4, json.loads(self._list("enceladus", {"all_projects": "true"})["body"])["count"])

    def test_state_filter(self):
        body = json.loads(self._list("*", {"state": "pending"})["body"])
        self.assertEqual({"DVP-ESC-001", "ENC-ESC-001"}, {e["item_id"] for e in body["escalations"]})
        body = json.loads(self._list("*", {"state": "expired,decided"})["body"])
        self.assertEqual({"DVP-ESC-002", "DVP-ESC-003"}, {e["item_id"] for e in body["escalations"]})

    def test_kind_filter(self):
        body = json.loads(self._list("*", {"kind": "tool_call"})["body"])
        self.assertEqual(["DVP-ESC-001"], [e["item_id"] for e in body["escalations"]])

    def test_invalid_filters_rejected(self):
        self.assertEqual(400, self._list("*", {"kind": "bogus"})["statusCode"])
        self.assertEqual(400, self._list("*", {"state": "bogus"})["statusCode"])

    def test_single_project_default_shape_unchanged(self):
        fake = self._ddb()
        with mock.patch.object(self.lf, "_get_ddb", return_value=fake):
            resp = self.lf._handle_escalation_list("enceladus", {})
        body = json.loads(resp["body"])
        self.assertEqual({"success", "escalations", "count"}, set(body))
        fake.scan.assert_not_called()  # no project enumeration for the default path

    def test_route_regex_accepts_cross_project_segments(self):
        rx = self.lf._RE_ESCALATION
        self.assertTrue(rx.match("/api/v1/tracker/*/escalation/list"))
        self.assertTrue(rx.match("/_/escalation"))
        self.assertTrue(rx.match("/api/v1/tracker/_/escalation/sweep"))


class TestFailClosedExpiry(_Base):
    def _apply(self, ddb):
        with mock.patch.object(self.lf, "_get_ddb", return_value=ddb):
            return self.lf._handle_escalation_apply(
                "enceladus", "ENC-ESC-001", {"write_source": {"provider": "ENC-SES-02F"}})

    def test_each_default_expires_exactly_at_ttl(self):
        created = dt.datetime(2026, 10, 1, 0, 0, 0, tzinfo=UTC)
        for kind, (ttl, _on) in F10.items():
            rec = {"kind": kind, "created_at": _z(created)}
            with self.subTest(kind=kind):
                self.assertFalse(self.lf._escalation_expiry(rec, created + ttl - dt.timedelta(seconds=1))["expired"])
                self.assertTrue(self.lf._escalation_expiry(rec, created + ttl)["expired"])

    def test_expired_approved_escalation_is_not_applied(self):
        ddb = _FakeDdb(escalation=_escalation_item(status="approved"), target=_target_task())
        # now = 2026-10-11 (pinned in setUp), record created 2026-07-02 -> expired
        resp = self._apply(ddb)
        self.assertEqual(410, resp["statusCode"])
        body = json.loads(resp["body"])
        self.assertEqual("expired", body["state"])
        self.assertEqual("2026-07-05T04:00:00Z", body["expiresAt"])
        self.assertEqual([], ddb.updates)  # no FSM transition, no applier write

    def test_expired_failed_retry_is_also_refused(self):
        ddb = _FakeDdb(escalation=_escalation_item(status="failed"), target=_target_task())
        self.assertEqual(410, self._apply(ddb)["statusCode"])
        self.assertEqual([], ddb.updates)

    def test_unexpired_explicit_expiry_still_applies(self):
        raw = _escalation_item(status="approved")
        raw["expiresAt"] = {"S": _z(NOW + dt.timedelta(hours=1))}
        ddb = _FakeDdb(escalation=raw, target=_target_task())
        resp = self._apply(ddb)
        self.assertEqual(200, resp["statusCode"], resp["body"])
        self.assertEqual(1, len(ddb.target_updates()))

    def test_already_applied_is_still_a_no_op_not_a_410(self):
        ddb = _FakeDdb(escalation=_escalation_item(status="applied", applied_at="2026-07-02T04:05:00Z"))
        resp = self._apply(ddb)
        self.assertEqual(200, resp["statusCode"])
        self.assertTrue(json.loads(resp["body"])["no_op"])


class TestExpirySweeper(_Base):
    def _ddb(self, items):
        fake = mock.MagicMock()
        fake.query.return_value = {"Items": items}
        fake.update_item.return_value = {}
        fake.scan.return_value = {"Items": [{"project_id": {"S": "enceladus"}}]}
        return fake

    def _sweep(self, project, items):
        ddb = self._ddb(items)
        with mock.patch.object(self.lf, "_get_ddb", return_value=ddb):
            resp = self.lf._handle_escalation_sweep(project, {})
        return resp, ddb

    def test_sweeps_only_expired_requested_and_moves_them_to_expired(self):
        stale = _escalation_item(status="requested")  # expired by NOW
        fresh = _escalation_item(status="requested")
        fresh["item_id"] = {"S": "ENC-ESC-002"}
        fresh["record_id"] = {"S": "escalation#ENC-ESC-002"}
        fresh["expiresAt"] = {"S": _z(NOW + dt.timedelta(hours=1))}
        resp, ddb = self._sweep("enceladus", [stale, fresh])
        body = json.loads(resp["body"])
        self.assertEqual(200, resp["statusCode"])
        self.assertEqual(1, body["swept_count"])
        self.assertEqual("ENC-ESC-001", body["swept"][0]["escalation_id"])
        self.assertEqual(1, ddb.update_item.call_count)
        kwargs = ddb.update_item.call_args.kwargs
        self.assertEqual("escalation#ENC-ESC-001", kwargs["Key"]["record_id"]["S"])
        self.assertEqual("expired", kwargs["ExpressionAttributeValues"][":to_status"]["S"])
        self.assertEqual("requested", kwargs["ExpressionAttributeValues"][":from_status"]["S"])
        event = kwargs["ExpressionAttributeValues"][":event"]["L"][0]["M"]
        self.assertEqual("expired", event["event_type"]["S"])
        self.assertEqual("system:escalation-expiry-sweeper", event["actor"]["S"])

    def test_sweeper_never_invokes_an_applier(self):
        stale = _escalation_item(status="requested")
        with mock.patch.dict(self.lf._ESCALATION_MUTATION_HANDLERS["deploy_arc_change"],
                             {"apply": mock.MagicMock()}) as handlers:
            self._sweep("enceladus", [stale])
            handlers["apply"].assert_not_called()

    def test_all_projects_sweep_enumerates_projects(self):
        resp, ddb = self._sweep("*", [])
        self.assertEqual(200, resp["statusCode"])
        ddb.scan.assert_called_once()

    def test_flag_off_503(self):
        with mock.patch.object(self.lf, "ENABLE_ESCALATION_PRIMITIVE", False):
            self.assertEqual(503, self.lf._handle_escalation_sweep("enceladus", {})["statusCode"])

    def test_expired_is_a_terminal_fsm_state(self):
        self.assertEqual(set(), self.lf._ESCALATION_FSM["expired"])
        self.assertIn("expired", self.lf._ESCALATION_FSM["requested"])
        self.assertNotIn("superseded", self.lf._ESCALATION_FSM)


if __name__ == "__main__":
    unittest.main()


try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None

_SCHEMA_PATH = __import__("os").path.join(
    __import__("os").path.dirname(__file__), "..", "..", "..", "tools",
    "enceladus-mcp-server", "parity", "schema", "gates.schema.json")


@unittest.skipUnless(jsonschema and __import__("os").path.exists(_SCHEMA_PATH), "jsonschema/schema unavailable")
class TestGatesSchemaContract(_Base):
    def setUp(self):
        super().setUp()
        self.schema = json.load(open(_SCHEMA_PATH))
        self.card = jsonschema.Draft202012Validator({**self.schema, "$ref": "#/$defs/GateCard"})

    def _sub(self, name):
        return jsonschema.Draft202012Validator({"$ref": f"#/$defs/{name}", "$defs": self.schema["$defs"]})

    def test_schema_is_valid_draft_2020_12_and_versioned(self):
        jsonschema.Draft202012Validator.check_schema(self.schema)
        self.assertIn("/v1/", self.schema["$id"])
        self.assertEqual("1.0.0", self.schema["x-schemaVersion"])

    def test_legacy_record_read_back_validates_as_a_gate_card(self):
        with mock.patch.object(self.lf, "_gate_now", return_value=dt.datetime(2026, 7, 2, 5, 0, tzinfo=UTC)):
            rec = self.lf._escalation_public(_escalation_item(status="requested"))
        self.card.validate(json.loads(json.dumps(rec)))

    def test_new_kind_record_validates_and_contradictions_do_not(self):
        raw = _escalation_item(status="requested")
        raw["kind"] = {"S": "limit"}
        raw["candidates"] = {"S": json.dumps([{"id": "raise", "label": "Raise limit"}])}
        raw["blastRadius"] = {"S": json.dumps({"records": 1, "stacks": ["enceladus"], "irreversible": False})}
        with mock.patch.object(self.lf, "_gate_now", return_value=dt.datetime(2026, 7, 2, 5, 0, tzinfo=UTC)):
            rec = json.loads(json.dumps(self.lf._escalation_public(raw)))
        self.card.validate(rec)
        self.assertFalse(self.card.is_valid(dict(rec, risk="severe")))
        self.assertFalse(self.card.is_valid(dict(rec, onExpire="auto_clear")))  # telemetry-only for decision family

    def test_telemetry_card_carries_no_proposed_action(self):
        tele = {"kind": "drift", "family": "telemetry", "risk": "low", "state": "pending",
                "subject": {"record_id": "ENC-TSK-1", "version": "v1"},
                "evidence": [{"label": "x", "ref": "y"}], "onExpire": "auto_clear"}
        self.assertTrue(self.card.is_valid(tele))
        self.assertFalse(self.card.is_valid(dict(tele, candidates=[{"id": "a", "label": "b"}])))

    def test_decide_request_and_list_query_defs(self):
        decide = self._sub("DecideRequest")
        self.assertTrue(decide.is_valid({"verdict": "approve", "ifMatch": "e1", "idempotencyKey": "k"}))
        self.assertFalse(decide.is_valid({"verdict": "deny", "ifMatch": "e1", "idempotencyKey": "k"}))  # reason
        self.assertTrue(decide.is_valid({"verdict": "deny", "ifMatch": "e1", "idempotencyKey": "k", "reason": "r"}))
        lst = self._sub("ListQuery")
        self.assertTrue(lst.is_valid({"project_id": "*", "state": "pending,expired", "kind": "tool_call"}))
        self.assertFalse(lst.is_valid({"state": "bogus"}))

    def test_decision_entry_requires_auth_method_auth_time_assurance(self):
        dec = self._sub("Decision")
        ok = {"decision": "approve", "decider": "io", "decidedAt": "2026-10-11T12:00:00Z",
              "auth_method": "step_up", "auth_time": "2026-10-11T11:59:00Z", "assurance": "aal2"}
        self.assertTrue(dec.is_valid(ok))
        # DVP-TSK-B34: the retired degraded-mode label is no longer a valid assurance.
        self.assertFalse(dec.is_valid(dict(ok, assurance="step_up_degraded")))
        for missing in ("auth_method", "auth_time", "assurance"):
            self.assertFalse(dec.is_valid({k: v for k, v in ok.items() if k != missing}))
