"""ENC-TSK-S39-0A: checkout_service -> tracker_mutation direct qualified invoke.

Run: PYTHONPATH=backend/lambda/shared_layer/python python3 -m pytest backend/lambda/checkout_service/test_direct_invoke_s39_0a.py -q
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import unittest
from unittest import mock

from botocore.exceptions import ClientError

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared_layer", "python"))
_SPEC = importlib.util.spec_from_file_location(
    "checkout_lambda_direct_invoke_s39_0a", os.path.join(os.path.dirname(__file__), "lambda_function.py"))
co = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = co
_SPEC.loader.exec_module(co)


def _lambda_resp(status=200, body=None, function_error=None):
    out = {"statusCode": status, "body": json.dumps(body if body is not None else {"success": True})}
    resp = {"Payload": io.BytesIO(json.dumps(out).encode())}
    if function_error:
        resp["FunctionError"] = function_error
    return resp


def _client_error(code):
    return ClientError({"Error": {"Code": code, "Message": "x"}}, "Invoke")


class _HttpResp:
    status = 200

    def read(self):
        return b'{"via": "http"}'

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class ModeSelectionTests(unittest.TestCase):
    def _mode(self, env):
        with mock.patch.dict(os.environ, env, clear=False):
            for k in ("CHECKOUT_TRACKER_INVOKE_MODE", "ENVIRONMENT_SUFFIX", "ENV_SUFFIX", "AWS_LAMBDA_FUNCTION_NAME"):
                if k not in env:
                    os.environ.pop(k, None)
            return co._tracker_invoke_mode(), co._tracker_function_name()

    def test_gamma_defaults_direct(self):
        self.assertEqual(self._mode({"AWS_LAMBDA_FUNCTION_NAME": "enceladus-checkout-service-gamma"}),
                         ("direct", "devops-tracker-mutation-api-gamma"))
        self.assertEqual(self._mode({"ENVIRONMENT_SUFFIX": "-gamma"})[0], "direct")

    def test_prod_and_local_default_http(self):
        self.assertEqual(self._mode({"AWS_LAMBDA_FUNCTION_NAME": "enceladus-checkout-service"}),
                         ("http", "devops-tracker-mutation-api"))
        self.assertEqual(self._mode({})[0], "http")

    def test_env_override_wins(self):
        self.assertEqual(self._mode({"CHECKOUT_TRACKER_INVOKE_MODE": "http",
                                     "AWS_LAMBDA_FUNCTION_NAME": "x-gamma"})[0], "http")
        self.assertEqual(self._mode({"CHECKOUT_TRACKER_INVOKE_MODE": "DIRECT"})[0], "direct")
        self.assertEqual(self._mode({"CHECKOUT_TRACKER_INVOKE_MODE": "bogus"})[0], "http")


class DirectInvokeTests(unittest.TestCase):
    def setUp(self):
        self.client = mock.Mock()
        patches = [
            mock.patch.object(co, "_get_lambda_client", return_value=self.client),
            mock.patch.object(co, "_tracker_invoke_mode", return_value="direct"),
            mock.patch.object(co, "_tracker_function_name", return_value="devops-tracker-mutation-api-gamma"),
            mock.patch.object(co, "_PRIMARY_INTERNAL_KEY", "key-new"),
            mock.patch.object(co, "_INTERNAL_API_KEYS", ("key-new", "key-old")),
            mock.patch.object(co, "CHECKOUT_SERVICE_KEY", "svc-key"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        co._WA.clear()
        co._WA.update({"correlation_id": "cid-1", "t": {}, "extra": {}, "enc_headers": {"x-enc-agent": "a1"}})
        self.addCleanup(co._WA.clear)

    def _http_patch(self):
        return mock.patch.object(co.urllib.request, "urlopen", return_value=_HttpResp())

    def test_direct_success_parses_status_and_body(self):
        self.client.invoke.return_value = _lambda_resp(200, {"success": True, "record": {"id": "T"}})
        with self._http_patch() as http:
            status, body = co._tracker_request("PATCH", "/enceladus/task/ENC-TSK-1", {"a": 1})
        self.assertEqual((status, body["record"]["id"]), (200, "T"))
        http.assert_not_called()
        kw = self.client.invoke.call_args.kwargs
        self.assertEqual(kw["FunctionName"], "devops-tracker-mutation-api-gamma:live")
        self.assertEqual(kw["InvocationType"], "RequestResponse")
        ev = json.loads(kw["Payload"])
        self.assertEqual((ev["version"], ev["routeKey"]), ("2.0", "$default"))
        self.assertEqual(ev["rawPath"], "/api/v1/tracker/enceladus/task/ENC-TSK-1")
        self.assertEqual(ev["requestContext"]["http"]["method"], "PATCH")
        h = ev["headers"]
        self.assertEqual(h["x-coordination-internal-key"], "key-new")
        self.assertEqual(h["x-checkout-service-key"], "svc-key")
        self.assertEqual(h["x-correlation-id"], "cid-1")
        self.assertEqual(h["x-enc-agent"], "a1")
        self.assertEqual(json.loads(ev["body"]), {"a": 1, "correlation_id": "cid-1"})
        self.assertEqual(co._WA["extra"]["invoke_mode"], "direct")
        self.assertEqual(co._WA["extra"]["hops"], 1)

    def test_query_string_split_from_path(self):
        self.client.invoke.return_value = _lambda_resp(200, {"items": []})
        co._tracker_request("GET", "/enceladus?record_type=task&status=open")
        ev = json.loads(self.client.invoke.call_args.kwargs["Payload"])
        self.assertEqual(ev["rawPath"], "/api/v1/tracker/enceladus")
        self.assertEqual(ev["queryStringParameters"], {"record_type": "task", "status": "open"})
        self.assertNotIn("body", ev)

    def test_transport_failure_falls_back_to_http_exactly_once(self):
        for exc in (_client_error("AccessDeniedException"), _client_error("ResourceNotFoundException"),
                    type("EndpointConnectionError", (Exception,), {})("no route")):
            self.client.invoke.reset_mock()
            self.client.invoke.side_effect = exc
            co._WA["extra"] = {}
            with self._http_patch() as http:
                status, body = co._tracker_request("POST", "/enceladus/task/T/log", {"x": 1})
            self.assertEqual((status, body), (200, {"via": "http"}))
            self.assertEqual(self.client.invoke.call_count, 1)
            self.assertEqual(http.call_count, 1)
            self.assertEqual(co._WA["extra"]["invoke_mode"], "direct_fallback")
            self.assertEqual(co._WA["extra"]["hops"], 2)

    def test_4xx_body_from_tool_does_not_fall_back(self):
        self.client.invoke.return_value = _lambda_resp(409, {"error": "version conflict"})
        with self._http_patch() as http:
            status, body = co._tracker_request("PATCH", "/enceladus/task/T", {"x": 1})
        self.assertEqual((status, body), (409, {"error": "version conflict"}))
        http.assert_not_called()
        self.assertEqual(co._WA["extra"]["invoke_mode"], "direct")

    def test_function_error_and_bad_response_do_not_fall_back(self):
        with self._http_patch() as http:
            self.client.invoke.return_value = {
                "Payload": io.BytesIO(json.dumps({"errorType": "Boom", "errorMessage": "bad"}).encode()),
                "FunctionError": "Unhandled",
            }
            status, body = co._tracker_request("POST", "/enceladus/task/T/log", {"x": 1})
            self.assertEqual(status, 500)
            self.assertIn("Boom", body["error"])
            self.client.invoke.return_value = {"Payload": io.BytesIO(b"not json")}
            status, _ = co._tracker_request("POST", "/enceladus/task/T/log", {"x": 1})
            self.assertEqual(status, 502)
        http.assert_not_called()

    def test_ambiguous_exception_does_not_fall_back(self):
        self.client.invoke.side_effect = type("ReadTimeoutError", (Exception,), {})("timed out")
        with self._http_patch() as http:
            status, body = co._tracker_request("POST", "/enceladus/task/T/log", {"x": 1})
        self.assertEqual(status, 503)
        self.assertIn("unavailable", body["error"])
        http.assert_not_called()
        self.assertEqual(co._WA["extra"]["invoke_mode"], "direct")

    def test_internal_key_rotation_on_401_403(self):
        for first in (401, 403):
            self.client.invoke.reset_mock()
            self.client.invoke.side_effect = [_lambda_resp(first, {"error": "denied"}), _lambda_resp(200, {"ok": 1})]
            status, body = co._tracker_request("PATCH", "/enceladus/task/T", {"x": 1})
            self.assertEqual((status, body), (200, {"ok": 1}))
            keys = [json.loads(c.kwargs["Payload"])["headers"]["x-coordination-internal-key"]
                    for c in self.client.invoke.call_args_list]
            self.assertEqual(keys, ["key-new", "key-old"])

    def test_rotation_exhausted_returns_last_denial(self):
        self.client.invoke.side_effect = [_lambda_resp(401, {"error": "d1"}), _lambda_resp(401, {"error": "d2"})]
        with self._http_patch() as http:
            status, body = co._tracker_request("PATCH", "/enceladus/task/T", {"x": 1})
        self.assertEqual((status, body), (401, {"error": "d2"}))
        http.assert_not_called()

    def test_http_mode_never_invokes(self):
        with mock.patch.object(co, "_tracker_invoke_mode", return_value="http"), self._http_patch() as http:
            status, body = co._tracker_request("PATCH", "/enceladus/task/T", {"x": 1})
        self.assertEqual((status, body), (200, {"via": "http"}))
        self.client.invoke.assert_not_called()
        http.assert_called_once()
        self.assertEqual((co._WA["extra"]["invoke_mode"], co._WA["extra"]["hops"]), ("http", 2))


class AuditLineTests(unittest.TestCase):
    def test_write_audit_line_carries_invoke_mode_and_t_invoke(self):
        import contextlib

        class Ctx:
            aws_request_id = "r"
            memory_limit_in_mb = 1024
            function_version = "1"

        client = mock.Mock()
        client.invoke.return_value = _lambda_resp(200, {"success": True})
        buf = io.StringIO()
        with mock.patch.object(co, "_get_lambda_client", return_value=client), \
                mock.patch.object(co, "_tracker_invoke_mode", return_value="direct"):
            co._wa_begin({"headers": {"x-correlation-id": "c9"}, "body": "{}"}, Ctx(), "checkout_service")
            co._tracker_request("PATCH", "/enceladus/task/T", {"x": 1})
            with contextlib.redirect_stdout(buf):
                co._wa_emit("checkout.advance", "enceladus", "T", 200)
        line = json.loads(buf.getvalue().split("[WRITE-AUDIT] ", 1)[1])
        self.assertEqual(line["invoke_mode"], "direct")
        self.assertEqual(line["hops"], 1)
        self.assertIn("t_invoke_ms", line)


if __name__ == "__main__":
    unittest.main()
