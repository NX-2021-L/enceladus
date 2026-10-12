"""DVP-TSK-A23: escalation web push (derived VAPID, routes, SNS-fed sender)."""
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402

import webpush as wp  # noqa: E402
from test_escalation_decision_j70 import coordination_lambda as lf  # noqa: E402

APPROVER = "io@example.com"
OTHER = "other@example.com"


class _UA:
    """A user agent: P-256 key + auth secret; can decrypt (RFC 8291 receive side)."""
    def __init__(self):
        self.priv = ec.generate_private_key(ec.SECP256R1())
        self.pub = self.priv.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        self.auth = os.urandom(16)
        self.keys = (wp.b64u(self.pub), wp.b64u(self.auth))

    def decrypt(self, body):
        salt, as_public = body[:16], body[21:21 + body[20]]
        ciphertext = body[21 + body[20]:]
        ecdh = self.priv.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), as_public))
        ikm = HKDF(hashes.SHA256(), 32, self.auth, b"WebPush: info\x00" + self.pub + as_public).derive(ecdh)
        cek = HKDF(hashes.SHA256(), 16, salt, b"Content-Encoding: aes128gcm\x00").derive(ikm)
        nonce = HKDF(hashes.SHA256(), 12, salt, b"Content-Encoding: nonce\x00").derive(ikm)
        plain = AESGCM(cek).decrypt(nonce, ciphertext, None)
        assert plain.endswith(b"\x02")
        return plain[:-1]


class _FakeTable:
    """Minimal low-level DynamoDB client over (pk, sk) items."""
    def __init__(self):
        self.items = {}

    def put_item(self, TableName, Item, **_):
        self.items[(Item["pk"]["S"], Item["sk"]["S"])] = dict(Item)

    def get_item(self, TableName, Key, **_):
        item = self.items.get((Key["pk"]["S"], Key["sk"]["S"]))
        return {"Item": item} if item else {}

    def delete_item(self, TableName, Key, **_):
        self.items.pop((Key["pk"]["S"], Key["sk"]["S"]), None)

    def query(self, TableName, ExpressionAttributeValues, **_):
        pk = ExpressionAttributeValues[":pk"]["S"]
        return {"Items": [v for (p, _s), v in sorted(self.items.items()) if p == pk]}


class DeriveVapidTests(unittest.TestCase):
    def test_deterministic_valid_p256_and_key_bound(self):
        a, b = wp.derive_vapid("secret-1"), wp.derive_vapid("secret-1")
        self.assertEqual(a, b)
        self.assertNotEqual(a["public"], wp.derive_vapid("secret-2")["public"])
        priv = ec.derive_private_key(int.from_bytes(wp.b64u_decode(a["private"]), "big"), ec.SECP256R1())
        pub = priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        self.assertEqual(wp.b64u(pub), a["public"])
        self.assertEqual(65, len(pub))

    def test_empty_key_refused(self):
        with self.assertRaises(ValueError):
            wp.derive_vapid("")

    def test_vapid_jwt_verifies_and_scopes_audience(self):
        v = wp.derive_vapid("k", "https://jreese.net")
        header = wp.vapid_headers("https://fcm.googleapis.com/fcm/send/abc", v, now=1000)["Authorization"]
        token = header.split("t=")[1].split(",")[0]
        h, c, s = token.split(".")
        claims = json.loads(wp.b64u_decode(c))
        self.assertEqual("https://fcm.googleapis.com", claims["aud"])
        self.assertEqual("https://jreese.net", claims["sub"])
        raw = wp.b64u_decode(s)
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), wp.b64u_decode(v["public"]))
        pub.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
                   f"{h}.{c}".encode(), ec.ECDSA(hashes.SHA256()))

    def test_aes128gcm_round_trip_and_framing(self):
        ua = _UA()
        body = wp.encrypt_aes128gcm(b'{"x":1}', *ua.keys)
        self.assertEqual((4096).to_bytes(4, "big"), body[16:20])
        self.assertEqual(b'{"x":1}', ua.decrypt(body))

    def test_endpoint_allow_list(self):
        self.assertTrue(wp.endpoint_allowed("https://fcm.googleapis.com/fcm/send/x"))
        self.assertTrue(wp.endpoint_allowed("https://updates.push.services.mozilla.com/wpush/v2/x"))
        for bad in ("http://fcm.googleapis.com/x", "https://evil.example.com/x", "https://fcm.googleapis.com.evil.io/x",
                    "https://user:p@fcm.googleapis.com/x", "https://fcm.googleapis.com/" + "a" * 2100, "", None):
            self.assertFalse(wp.endpoint_allowed(bad), bad)


def _claims(email=APPROVER):
    return {"email": email, "token_use": "id", "sub": "s"}


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.table = _FakeTable()
        self.ua = _UA()
        self.sub = {"endpoint": "https://fcm.googleapis.com/fcm/send/abc",
                    "keys": {"p256dh": self.ua.keys[0], "auth": self.ua.keys[1]}}
        patches = [
            mock.patch.object(lf, "_get_ddb", return_value=self.table),
            mock.patch.object(lf, "_is_cognito_session", return_value=True),
            mock.patch.object(lf, "_is_human_cognito_principal", return_value=True),
            mock.patch.object(lf, "_load_escalation_approver_allowlist", return_value={APPROVER}),
            mock.patch.dict(os.environ, {"COORDINATION_INTERNAL_API_KEY": "route-key"}),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def call(self, method, name, body=None, email=APPROVER):
        path = f"/api/v1/coordination/notifications/{name}"
        event = {"body": json.dumps(body) if body is not None else None, "headers": {}}
        resp = lf._handle_notifications(method, path, event, _claims(email))
        return resp["statusCode"], json.loads(resp["body"])

    def test_non_approver_refused_on_every_route(self):
        for method, name in (("GET", "vapid-public-key"), ("POST", "subscribe"),
                             ("DELETE", "subscribe"), ("GET", "preferences"), ("PUT", "preferences")):
            code, _ = self.call(method, name, {"subscription": self.sub}, email=OTHER)
            self.assertEqual(403, code, (method, name))
        self.assertEqual({}, self.table.items)

    def test_vapid_public_key_matches_derivation(self):
        code, body = self.call("GET", "vapid-public-key")
        self.assertEqual(200, code)
        self.assertEqual(wp.derive_vapid("route-key")["public"], body["public_key"])

    def test_subscribe_unsubscribe_round_trip(self):
        self.assertEqual(200, self.call("POST", "subscribe", {"subscription": self.sub})[0])
        self.assertEqual(200, self.call("POST", "subscribe", self.sub)[0])  # idempotent, bare form
        keys = [k for k in self.table.items if k[0] == f"PUSHSUB#{APPROVER}"]
        self.assertEqual(1, len(keys))
        self.assertEqual(64, len(keys[0][1]))
        self.assertEqual(200, self.call("DELETE", "subscribe", {"endpoint": self.sub["endpoint"]})[0])
        self.assertEqual([], [k for k in self.table.items if k[0].startswith("PUSHSUB#")])

    def test_subscribe_validation(self):
        bad = dict(self.sub, endpoint="https://evil.example.com/x")
        self.assertEqual(400, self.call("POST", "subscribe", {"subscription": bad})[0])
        self.assertEqual(400, self.call("POST", "subscribe", {"subscription": {"endpoint": self.sub["endpoint"]}})[0])
        self.assertEqual(400, self.call("DELETE", "subscribe", {})[0])

    def test_preferences_defaults_round_trip_and_validation(self):
        code, body = self.call("GET", "preferences")
        self.assertEqual((200, True, "low"), (code, body["enabled"], body["extra"]["min_risk"]))
        put = {"enabled": True, "types": {"acceptance": {"enabled": False, "level": 0}},
               "extra": {"min_risk": "high"}}
        self.assertEqual(200, self.call("PUT", "preferences", put)[0])
        _, body = self.call("GET", "preferences")
        self.assertEqual({"enabled": False, "level": 0}, body["types"]["acceptance"])
        self.assertEqual("high", body["extra"]["min_risk"])
        for bad in ({"enabled": "yes"}, {"extra": {"min_risk": "nope"}},
                    {"types": {"acceptance": {"level": 2}}}, {"types": {"Bad Kind": {}}}):
            self.assertEqual(400, self.call("PUT", "preferences", bad)[0], bad)


class SenderTests(unittest.TestCase):
    def setUp(self):
        self.table = _FakeTable()
        self.sent = []
        self.status = {}
        self.uas = {}
        self.escalation = {"escalation_id": "ESC-1", "project_id": "enceladus", "status": "requested",
                           "kind": "acceptance", "risk": "high", "justification": "Promote X to prod " + "y" * 200}
        patches = [
            mock.patch.object(lf, "_get_ddb", return_value=self.table),
            mock.patch.object(lf, "_read_escalation_item", side_effect=lambda p, e: dict(self.escalation)),
            mock.patch.object(lf, "_load_escalation_approver_allowlist", return_value={APPROVER, "two@example.com"}),
            mock.patch.object(lf, "_notify_pending_count", return_value=3),
            mock.patch.object(lf, "APP_BASE_URL", "https://jreese.net/"),
            mock.patch.object(lf._webpush, "http_send", side_effect=self._http_send),
            mock.patch.dict(os.environ, {"COORDINATION_INTERNAL_API_KEY": "sender-key"}),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def _http_send(self, endpoint, body, headers):
        if self.status.get(endpoint) == "raise":
            raise OSError("boom")
        self.sent.append((endpoint, body, headers))
        return self.status.get(endpoint, 201)

    def subscribe(self, email, n):
        ua = _UA()
        endpoint = f"https://fcm.googleapis.com/fcm/send/{email}-{n}"
        self.uas[endpoint] = ua
        import hashlib
        self.table.put_item("t", {"pk": {"S": f"PUSHSUB#{email}"}, "sk": {"S": hashlib.sha256(endpoint.encode()).hexdigest()},
                                  "endpoint": {"S": endpoint}, "p256dh": {"S": ua.keys[0]}, "auth": {"S": ua.keys[1]}})
        return endpoint

    def prefs(self, email, prefs):
        self.table.put_item("t", {"pk": {"S": f"PUSHPREF#{email}"}, "sk": {"S": "prefs"},
                                  "doc": {"S": json.dumps(prefs)}})

    def sns(self, event="requested", esc="ESC-1", project="enceladus"):
        attrs = {"escalation_event": {"Type": "String", "Value": event},
                 "escalation_id": {"Type": "String", "Value": esc},
                 "project_id": {"Type": "String", "Value": project}}
        return {"Records": [{"EventSource": "aws:sns", "Sns": {"MessageAttributes": attrs}}]}

    def payloads(self):
        return [json.loads(self.uas[e].decrypt(b)) for e, b, _h in self.sent]

    def test_lambda_handler_routes_sns_events_to_the_sender(self):
        self.subscribe(APPROVER, 1)
        resp = lf.lambda_handler(self.sns(), None)
        self.assertEqual(1, resp["sent"])

    def test_one_push_per_subscription_with_deep_link_and_level1_body(self):
        self.subscribe(APPROVER, 1)
        self.subscribe(APPROVER, 2)
        self.subscribe("two@example.com", 1)
        self.assertEqual(3, lf._handle_escalation_push_sns(self.sns())["sent"])
        for p in self.payloads():
            n = p["notification"]
            self.assertEqual(8030, p["web_push"])
            self.assertEqual("https://jreese.net/escalations/ESC-1", n["navigate"])
            self.assertEqual("ESC-1", n["tag"])
            self.assertEqual(3, n["app_badge"])
            self.assertEqual("Escalation · high", n["title"])
            self.assertTrue(n["body"].startswith("enceladus: acceptance — Promote X to prod"))
            self.assertLessEqual(len(n["body"].split(" — ", 1)[1]), 120)

    def test_level0_is_generic(self):
        self.subscribe(APPROVER, 1)
        self.prefs(APPROVER, {"enabled": True, "types": {"acceptance": {"enabled": True, "level": 0}},
                              "extra": {"min_risk": "low"}})
        lf._handle_escalation_push_sns(self.sns())
        self.assertEqual("A decision is waiting in Enceladus", self.payloads()[0]["notification"]["body"])

    def test_preferences_gate_enabled_kind_and_min_risk(self):
        self.subscribe(APPROVER, 1)
        self.subscribe("two@example.com", 1)
        self.prefs(APPROVER, {"enabled": False, "types": {}, "extra": {"min_risk": "low"}})
        self.prefs("two@example.com", {"enabled": True, "types": {"acceptance": {"enabled": False, "level": 1}},
                                       "extra": {"min_risk": "low"}})
        self.assertEqual(0, lf._handle_escalation_push_sns(self.sns())["sent"])
        self.prefs("two@example.com", {"enabled": True, "types": {}, "extra": {"min_risk": "critical"}})
        self.assertEqual(0, lf._handle_escalation_push_sns(self.sns())["sent"])
        self.prefs("two@example.com", {"enabled": True, "types": {}, "extra": {"min_risk": "high"}})
        self.assertEqual(1, lf._handle_escalation_push_sns(self.sns())["sent"])

    def test_non_requested_events_and_non_pending_send_nothing(self):
        self.subscribe(APPROVER, 1)
        for ev in ("applied", "failed", "expired"):
            self.assertEqual(0, lf._handle_escalation_push_sns(self.sns(event=ev))["sent"])
        self.escalation["status"] = "approved"
        self.assertEqual(0, lf._handle_escalation_push_sns(self.sns())["sent"])
        self.assertEqual([], self.sent)

    def test_dead_endpoints_pruned_and_failures_isolated(self):
        dead = self.subscribe(APPROVER, 1)
        gone = self.subscribe(APPROVER, 2)
        boom = self.subscribe(APPROVER, 3)
        ok = self.subscribe(APPROVER, 4)
        self.status.update({dead: 410, gone: 404, boom: "raise"})
        self.assertEqual(1, lf._handle_escalation_push_sns(self.sns())["sent"])
        remaining = {v["endpoint"]["S"] for (p, _s), v in self.table.items.items() if p.startswith("PUSHSUB#")}
        self.assertEqual({boom, ok}, remaining)

    def test_handler_never_raises(self):
        with mock.patch.object(lf, "_read_escalation_item", side_effect=RuntimeError("ddb down")):
            self.assertTrue(lf._handle_escalation_push_sns(self.sns())["success"])
        with mock.patch.object(lf, "_load_escalation_approver_allowlist", side_effect=RuntimeError("s3")):
            self.assertTrue(lf._handle_escalation_push_sns(self.sns())["success"])
        self.assertTrue(lf._handle_escalation_push_sns({"Records": [{"EventSource": "aws:sns"}]})["success"])


if __name__ == "__main__":
    unittest.main()
