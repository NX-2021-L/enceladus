"""ENC-TSK-S39-0C: nested lifecycle/id-service invokes are alias-qualified and timed."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import sys
import unittest
from unittest import mock

os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
sys.path.insert(0, os.path.dirname(__file__))

_spec = importlib.util.spec_from_file_location(
    "tracker_mutation_nested_s39_0c", os.path.join(os.path.dirname(__file__), "lambda_function.py"))
tm = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = tm
_spec.loader.exec_module(tm)


class _Ctx:
    aws_request_id = "req-1"
    memory_limit_in_mb = 512
    function_version = "$LATEST"


def _client(verdict):
    c = mock.Mock()
    c.invoke.return_value = {"Payload": io.BytesIO(json.dumps(verdict).encode())}
    return c


class NestedInvokeTests(unittest.TestCase):
    def _run(self, qualifier):
        env = {} if qualifier is None else {"NESTED_INVOKE_QUALIFIER": qualifier}
        if qualifier is None:
            os.environ.pop("NESTED_INVOKE_QUALIFIER", None)
        with mock.patch.dict(os.environ, env), \
                mock.patch.object(tm, "LIFECYCLE_SERVICE_FUNCTION", "enceladus-lifecycle-service"), \
                mock.patch.object(tm, "ID_SERVICE_FUNCTION", "enceladus-id-service"):
            lc, idc = _client({"allow": True}), _client({"allow": True})
            with mock.patch.object(tm, "_get_lambda_client", side_effect=[lc, idc, lc]):
                tm._invoke_lifecycle_service({"a": 1})
                tm._invoke_id_service({"a": 1})
                tm._invoke_lifecycle_action({"a": 1})
            return lc, idc

    def test_default_live_qualifier(self):
        lc, idc = self._run(None)
        self.assertEqual(lc.invoke.call_args_list[0].kwargs["FunctionName"], "enceladus-lifecycle-service:live")
        self.assertEqual(lc.invoke.call_args_list[1].kwargs["FunctionName"], "enceladus-lifecycle-service:live")
        self.assertEqual(idc.invoke.call_args.kwargs["FunctionName"], "enceladus-id-service:live")

    def test_empty_qualifier_is_unqualified(self):
        lc, idc = self._run("")
        self.assertEqual(lc.invoke.call_args.kwargs["FunctionName"], "enceladus-lifecycle-service")
        self.assertEqual(idc.invoke.call_args.kwargs["FunctionName"], "enceladus-id-service")

    def test_timing_fields_on_audit_line(self):
        def inner(event, context):
            tm._WA["version_seq"] = 1
            with mock.patch.object(tm, "LIFECYCLE_SERVICE_FUNCTION", "lc"), \
                    mock.patch.object(tm, "ID_SERVICE_FUNCTION", "ids"), \
                    mock.patch.object(tm, "_get_lambda_client", return_value=_client({"allow": True})):
                tm._invoke_lifecycle_service({})
                tm._invoke_id_service({})
            return {"statusCode": 201, "body": json.dumps({"record_id": "ENC-TSK-9"})}

        def run(inner_fn):
            buf = io.StringIO()
            ev = {"httpMethod": "POST", "rawPath": "/api/v1/tracker/enceladus/task", "headers": {}, "body": "{}"}
            with mock.patch.object(tm, "_lambda_handler_inner", inner_fn), contextlib.redirect_stdout(buf):
                tm.lambda_handler(ev, _Ctx())
            return json.loads(buf.getvalue().split("[WRITE-AUDIT] ", 1)[1].splitlines()[0])

        line = run(inner)
        self.assertIn("t_lifecycle_ms", line)
        self.assertIn("t_id_service_ms", line)
        # when not called the fields are present and 0
        idle = run(lambda e, c: {"statusCode": 200, "body": "{}"})
        self.assertEqual((idle["t_lifecycle_ms"], idle["t_id_service_ms"]), (0, 0))


if __name__ == "__main__":
    unittest.main()
