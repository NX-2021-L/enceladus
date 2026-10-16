"""ENC-TSK-Q83: notify v2 (per-device subscriptions, prefs, test route, per-device sender)."""
import hashlib
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from jsonschema import Draft202012Validator, FormatChecker  # noqa: E402

from test_notifications_a23 import APPROVER, OTHER, _UA, _claims, _FakeTable  # noqa: E402
from test_escalation_decision_j70 import coordination_lambda as lf  # noqa: E402
import notify_v2  # noqa: E402

_SCHEMA_PATH = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "contracts", "notify", "v2", "notify.schema.json"))
with open(_SCHEMA_PATH) as _fh:
    SCHEMA = json.load(_fh)


def validate(ref, instance):
    """Validate against a $defs ref such as '#/$defs/device'."""
    name = ref.rsplit("/", 1)[1]
    Draft202012Validator({"$ref": f"#/$defs/{name}", "$defs": SCHEMA["$defs"]},
                         format_checker=FormatChecker()).validate(instance)


class _Table(_FakeTable):
    def update_item(self, TableName, Key, UpdateExpression, ExpressionAttributeValues, **kw):
        item = self.items[(Key["pk"]["S"], Key["sk"]["S"])]
        names = kw.get("ExpressionAttributeNames") or {}
        field = UpdateExpression.split("SET ", 1)[1].split("=", 1)[0].strip()
        item[names.get(field, field)] = list(ExpressionAttributeValues.values())[0]


class Base(unittest.TestCase):
    def setUp(self):
        self.table = _Table()
        self.sent = []
        self.status = {}
        self.uas = {}
        patches = [
            mock.patch.object(lf, "_get_ddb", return_value=self.table),
            mock.patch.object(lf, "_is_cognito_session", return_value=True),
            mock.patch.object(lf, "_is_human_cognito_principal", return_value=True),
            mock.patch.object(lf, "_load_escalation_approver_allowlist", return_value={APPROVER}),
            mock.patch.object(lf._webpush, "http_send", side_effect=self._http_send),
            mock.patch.dict(os.environ, {"COORDINATION_INTERNAL_API_KEY": "q83-key"}),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def _http_send(self, endpoint, body, headers):
        if self.status.get(endpoint) == "raise":
            raise OSError("boom")
        self.sent.append((endpoint, body, headers))
        return self.status.get(endpoint, 201)

    def sub_body(self, device_id="dev-aaaaaaaa", label="iPhone", platform="ios", n=None):
        ua = _UA()
        endpoint = f"https://fcm.googleapis.com/fcm/send/{n or device_id}"
        self.uas[endpoint] = ua
        return {"device_id": device_id, "label": label, "platform": platform,
                "subscription": {"endpoint": endpoint, "keys": {"p256dh": ua.keys[0], "auth": ua.keys[1]}}}

    def call(self, method, name, body=None, email=APPROVER):
        path = f"/api/v1/coordination/notifications/{name}"
        event = {"body": json.dumps(body) if body is not None else None, "headers": {}}
        resp = notify_v2.handle(lf, method, path, event, _claims(email))
        return resp["statusCode"], (json.loads(resp["body"]) if resp["body"] else None)

    def subscribe(self, **kw):
        body = self.sub_body(**kw)
        code, out = self.call("POST", "subscribe", body)
        self.assertEqual(200, code, out)
        return body


class RouteTests(Base):
    def test_non_approver_refused_everywhere(self):
        for m, n in (("GET", "vapid-public-key"), ("POST", "subscribe"), ("GET", "devices"),
                     ("GET", "devices/dev-aaaaaaaa/preferences"), ("PUT", "devices/dev-aaaaaaaa/preferences"),
                     ("PATCH", "devices/dev-aaaaaaaa"), ("DELETE", "devices/dev-aaaaaaaa"),
                     ("POST", "devices/dev-aaaaaaaa/test")):
            self.assertEqual(403, self.call(m, n, {}, email=OTHER)[0], (m, n))
        self.assertEqual({}, self.table.items)

    def test_vapid_key(self):
        code, body = self.call("GET", "vapid-public-key")
        self.assertEqual(200, code)
        validate("#/$defs/VapidPublicKeyResponse", body)
        self.assertEqual(405, self.call("POST", "vapid-public-key")[0])

    def test_subscribe_happy_default_all_off_and_schema(self):
        body = self.sub_body()
        validate("#/$defs/subscribeRequest", body)
        code, out = self.call("POST", "subscribe", body)
        self.assertEqual(200, code)
        validate("#/$defs/device", out)
        self.assertIsNone(out["last_sent_at"])
        code, prefs = self.call("GET", "devices/dev-aaaaaaaa/preferences")
        self.assertEqual((200, {}), (code, prefs["types"]))
        validate("#/$defs/devicePreferences", prefs)
        row = self.table.items[(f"PUSHDEV#{APPROVER}", "dev-aaaaaaaa")]
        self.assertEqual(64, len(row["endpoint_hash"]["S"]))

    def test_subscribe_errors(self):
        good = self.sub_body()
        for mutate in (lambda b: b.pop("device_id"), lambda b: b.update(device_id="short"),
                       lambda b: b.pop("label"), lambda b: b.update(label="x" * 65),
                       lambda b: b.update(platform="android"),
                       lambda b: b["subscription"].update(endpoint="https://evil.example.com/x"),
                       lambda b: b["subscription"].pop("keys")):
            b = json.loads(json.dumps(good))
            mutate(b)
            self.assertEqual(400, self.call("POST", "subscribe", b)[0])
        self.assertEqual(405, self.call("GET", "subscribe")[0])
        self.assertEqual({}, self.table.items)

    def test_resubscribe_keeps_prefs_and_label(self):
        self.subscribe()
        prefs = {"types": {"acceptance": {"enabled": True, "min_risk": "high"}}, "detail": "generic"}
        self.assertEqual(200, self.call("PUT", "devices/dev-aaaaaaaa/preferences", prefs)[0])
        again = self.sub_body(label="Renamed phone", n="newendpoint")
        code, out = self.call("POST", "subscribe", again)
        self.assertEqual((200, "iPhone"), (code, out["label"]))
        row = self.table.items[(f"PUSHDEV#{APPROVER}", "dev-aaaaaaaa")]
        self.assertEqual(again["subscription"]["endpoint"], row["endpoint"]["S"])
        self.assertEqual(prefs, self.call("GET", "devices/dev-aaaaaaaa/preferences")[1])

    def test_devices_list(self):
        self.subscribe()
        self.subscribe(device_id="dev-bbbbbbbb", label="Mac", platform="macos")
        code, out = self.call("GET", "devices")
        self.assertEqual(200, code)
        validate("#/$defs/deviceList", out)
        self.assertEqual(2, len(out["devices"]))
        self.assertEqual(405, self.call("POST", "devices")[0])

    def test_preferences_put_get_and_validation(self):
        self.subscribe()
        put = {"types": {"acceptance": {"enabled": True, "min_risk": "critical"}}, "detail": "generic"}
        validate("#/$defs/devicePreferences", put)
        code, out = self.call("PUT", "devices/dev-aaaaaaaa/preferences", put)
        self.assertEqual((200, put), (code, out))
        self.assertEqual(put, self.call("GET", "devices/dev-aaaaaaaa/preferences")[1])
        for bad in ({"types": {}, "detail": "verbose"},
                    {"types": {"a": {"enabled": True, "min_risk": "nope"}}, "detail": "generic"},
                    {"types": {"Bad Kind": {"enabled": True, "min_risk": "low"}}, "detail": "generic"},
                    {"types": {"a": {"enabled": "yes", "min_risk": "low"}}, "detail": "generic"},
                    {"types": {"a": {"enabled": True}}, "detail": "generic"},
                    {"detail": "generic"}, []):
            self.assertEqual(400, self.call("PUT", "devices/dev-aaaaaaaa/preferences", bad)[0], bad)
        self.assertEqual(404, self.call("GET", "devices/dev-zzzzzzzz/preferences")[0])
        self.assertEqual(405, self.call("DELETE", "devices/dev-aaaaaaaa/preferences")[0])

    def test_per_type_detail_roundtrip_and_validation(self):
        self.subscribe()
        put = {"types": {"acceptance": {"enabled": True, "min_risk": "low", "detail": "generic"}},
               "detail": "detailed"}
        validate("#/$defs/devicePreferences", put)
        self.assertEqual((200, put), self.call("PUT", "devices/dev-aaaaaaaa/preferences", put))
        self.assertEqual(put, self.call("GET", "devices/dev-aaaaaaaa/preferences")[1])
        bad = {"types": {"acceptance": {"enabled": True, "min_risk": "low", "detail": "verbose"}},
               "detail": "detailed"}
        self.assertEqual(400, self.call("PUT", "devices/dev-aaaaaaaa/preferences", bad)[0])
        extra = {"types": {"acceptance": {"enabled": True, "min_risk": "low", "x": 1}}, "detail": "detailed"}
        self.assertEqual(400, self.call("PUT", "devices/dev-aaaaaaaa/preferences", extra)[0])

    def test_rename(self):
        self.subscribe()
        code, out = self.call("PATCH", "devices/dev-aaaaaaaa", {"label": "Work phone"})
        self.assertEqual((200, "Work phone"), (code, out["label"]))
        validate("#/$defs/device", out)
        self.assertEqual("Work phone", self.call("GET", "devices")[1]["devices"][0]["label"])
        for bad in ({}, {"label": ""}, {"label": "x" * 65}, {"label": "a", "x": 1}):
            self.assertEqual(400, self.call("PATCH", "devices/dev-aaaaaaaa", bad)[0], bad)
        self.assertEqual(404, self.call("PATCH", "devices/dev-zzzzzzzz", {"label": "a"})[0])

    def test_delete(self):
        self.subscribe()
        self.assertEqual((204, None), self.call("DELETE", "devices/dev-aaaaaaaa"))
        self.assertEqual([], self.call("GET", "devices")[1]["devices"])
        self.assertEqual(404, self.call("DELETE", "devices/dev-aaaaaaaa")[0])

    def test_test_route(self):
        body = self.subscribe()
        self.subscribe(device_id="dev-bbbbbbbb")
        code, out = self.call("POST", "devices/dev-aaaaaaaa/test")
        self.assertEqual((200, True, 201), (code, out["sent"], out["status_code"]))
        validate("#/$defs/testResponse", out)
        self.assertEqual([body["subscription"]["endpoint"]], [s[0] for s in self.sent])  # only that device
        payload = json.loads(self.uas[self.sent[0][0]].decrypt(self.sent[0][1]))
        validate("#/$defs/DeclarativePushPayload", payload)
        self.assertIsNotNone(self.call("GET", "devices")[1]["devices"][0]["last_sent_at"])
        self.status[body["subscription"]["endpoint"]] = 500
        self.assertEqual({"sent": False, "status_code": 500}, self.call("POST", "devices/dev-aaaaaaaa/test")[1])
        self.status[body["subscription"]["endpoint"]] = "raise"
        self.assertEqual({"sent": False, "status_code": None}, self.call("POST", "devices/dev-aaaaaaaa/test")[1])
        self.status[body["subscription"]["endpoint"]] = 410
        self.assertEqual(410, self.call("POST", "devices/dev-aaaaaaaa/test")[1]["status_code"])
        self.assertEqual(404, self.call("POST", "devices/dev-aaaaaaaa/test")[0])
        self.assertEqual(405, self.call("GET", "devices/dev-bbbbbbbb/test")[0])

    def test_removed_v1_routes_return_410(self):
        for m, n in (("GET", "preferences"), ("PUT", "preferences"), ("DELETE", "subscribe")):
            code, body = self.call(m, n, {})
            self.assertEqual(410, code, (m, n))
            self.assertIn("devices", body["error"])

    def test_unknown_subroute_404(self):
        self.assertEqual(404, self.call("GET", "nonsense")[0])
        self.assertEqual(404, self.call("GET", "devices/dev-aaaaaaaa/other")[0])

    def test_legacy_purge_on_first_subscribe_idempotent(self):
        for pk, sk in ((f"PUSHSUB#{APPROVER}", "h1"), (f"PUSHSUB#{APPROVER}", "h2"), (f"PUSHPREF#{APPROVER}", "prefs"),
                       ("PUSHSUB#other@example.com", "h3")):
            self.table.put_item("t", {"pk": {"S": pk}, "sk": {"S": sk}})
        self.subscribe()
        left = {k[0] for k in self.table.items}
        self.assertEqual({f"PUSHDEV#{APPROVER}", "PUSHSUB#other@example.com"}, left)
        self.assertEqual(0, notify_v2._purge_legacy_push_rows(APPROVER))
        # GET devices ignores legacy rows
        self.table.put_item("t", {"pk": {"S": f"PUSHSUB#{APPROVER}"}, "sk": {"S": "z"}})
        self.assertEqual(1, len(self.call("GET", "devices")[1]["devices"]))


class SenderTests(Base):
    def setUp(self):
        super().setUp()
        self.escalation = {"escalation_id": "ESC-1", "project_id": "enceladus", "status": "requested",
                           "kind": "acceptance", "risk": "high", "justification": "Promote X to prod"}
        for p in (mock.patch.object(lf, "_read_escalation_item", side_effect=lambda p, e: dict(self.escalation)),
                  mock.patch.object(notify_v2, "_notify_pending_count", return_value=2)):
            p.start()
            self.addCleanup(p.stop)

    def sns(self):
        attrs = {"escalation_event": {"Value": "requested"}, "escalation_id": {"Value": "ESC-1"},
                 "project_id": {"Value": "enceladus"}}
        return {"Records": [{"EventSource": "aws:sns", "Sns": {"MessageAttributes": attrs}}]}

    def optin(self, device_id, detail="detailed", kind="acceptance", min_risk="low", enabled=True):
        prefs = {"types": {kind: {"enabled": enabled, "min_risk": min_risk}}, "detail": detail}
        self.assertEqual(200, self.call("PUT", f"devices/{device_id}/preferences", prefs)[0])

    def payloads(self):
        return {e: json.loads(self.uas[e].decrypt(b)) for e, b, _h in self.sent}

    def test_all_off_by_default(self):
        self.subscribe()
        self.assertEqual(0, lf.notify_v2.handle_escalation_push_sns(lf, self.sns())["sent"])
        self.assertEqual([], self.sent)

    def test_per_device_isolation_and_detail(self):
        a, b = self.subscribe(), self.subscribe(device_id="dev-bbbbbbbb")
        c = self.subscribe(device_id="dev-cccccccc")
        self.optin("dev-aaaaaaaa", "detailed")
        self.optin("dev-cccccccc", "generic")
        self.assertEqual(2, lf.notify_v2.handle_escalation_push_sns(lf, self.sns())["sent"])
        got = self.payloads()
        self.assertNotIn(b["subscription"]["endpoint"], got)
        da = got[a["subscription"]["endpoint"]]["notification"]
        dc = got[c["subscription"]["endpoint"]]["notification"]
        validate("#/$defs/DeclarativePushPayload", got[a["subscription"]["endpoint"]])
        self.assertTrue(da["body"].startswith("enceladus: acceptance — Promote X"))
        self.assertEqual("Escalation · high", da["title"])
        self.assertEqual("New escalation awaiting your decision", dc["body"])
        self.assertNotIn("Promote", json.dumps(dc))
        self.assertNotIn("enceladus:", dc["body"])
        self.assertIsNotNone(self.call("GET", "devices")[1]["devices"][0]["last_sent_at"])

    def test_per_type_detail_overrides_device_detail(self):
        a = self.subscribe()
        prefs = {"types": {"acceptance": {"enabled": True, "min_risk": "low", "detail": "generic"}},
                 "detail": "detailed"}
        self.assertEqual(200, self.call("PUT", "devices/dev-aaaaaaaa/preferences", prefs)[0])
        self.assertEqual(1, lf.notify_v2.handle_escalation_push_sns(lf, self.sns())["sent"])
        body = self.payloads()[a["subscription"]["endpoint"]]["notification"]["body"]
        self.assertEqual("New escalation awaiting your decision", body)

    def test_type_without_detail_falls_back_to_device_detail(self):
        a = self.subscribe()
        self.optin("dev-aaaaaaaa", "detailed")
        self.assertEqual(1, lf.notify_v2.handle_escalation_push_sns(lf, self.sns())["sent"])
        body = self.payloads()[a["subscription"]["endpoint"]]["notification"]["body"]
        self.assertTrue(body.startswith("enceladus: acceptance"))

    def test_other_kind_and_disabled_not_sent(self):
        self.subscribe()
        self.optin("dev-aaaaaaaa", kind="deploy")
        self.assertEqual(0, lf.notify_v2.handle_escalation_push_sns(lf, self.sns())["sent"])
        self.optin("dev-aaaaaaaa", enabled=False)
        self.assertEqual(0, lf.notify_v2.handle_escalation_push_sns(lf, self.sns())["sent"])

    def test_min_risk_filter(self):
        self.subscribe()
        self.optin("dev-aaaaaaaa", min_risk="critical")
        self.assertEqual(0, lf.notify_v2.handle_escalation_push_sns(lf, self.sns())["sent"])
        self.optin("dev-aaaaaaaa", min_risk="high")
        self.assertEqual(1, lf.notify_v2.handle_escalation_push_sns(lf, self.sns())["sent"])

    def test_410_and_404_pruned_failures_isolated(self):
        bodies = [self.subscribe(device_id=f"dev-{c}{c}{c}{c}{c}{c}{c}{c}") for c in "abcd"]
        for b in bodies:
            self.optin(b["device_id"])
        self.status[bodies[0]["subscription"]["endpoint"]] = 410
        self.status[bodies[1]["subscription"]["endpoint"]] = 404
        self.status[bodies[2]["subscription"]["endpoint"]] = "raise"
        self.assertEqual(1, lf.notify_v2.handle_escalation_push_sns(lf, self.sns())["sent"])
        left = {k[1] for k in self.table.items if k[0].startswith("PUSHDEV#")}
        self.assertEqual({bodies[2]["device_id"], bodies[3]["device_id"]}, left)

    def test_legacy_rows_ignored_by_sender(self):
        ua = _UA()
        ep = "https://fcm.googleapis.com/fcm/send/legacy"
        self.table.put_item("t", {"pk": {"S": f"PUSHSUB#{APPROVER}"}, "sk": {"S": hashlib.sha256(ep.encode()).hexdigest()},
                                  "endpoint": {"S": ep}, "p256dh": {"S": ua.keys[0]}, "auth": {"S": ua.keys[1]}})
        self.assertEqual(0, lf.notify_v2.handle_escalation_push_sns(lf, self.sns())["sent"])


if __name__ == "__main__":
    unittest.main()
