"""test_auto_checkout_circuit_breaker.py — ENC-TSK-R29.

handler_auto_checkout (EventBridge enceladus-checkout-auto, rate 5 min) must
stop the run on the first non-2xx _checkout_task response instead of issuing
one failing POST per candidate (the 405 storm since 94c990fa). The success
path is unchanged.

Run: python3 -m pytest test_auto_checkout_circuit_breaker.py -q
"""

import importlib.util
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared_layer", "python"))
_SPEC = importlib.util.spec_from_file_location(
    "checkout_lambda_auto_breaker",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
checkout_lambda = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
sys.modules[_SPEC.name] = checkout_lambda
_SPEC.loader.exec_module(checkout_lambda)


def _stale_task(task_id: str) -> dict:
    ts = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"id": task_id, "active_agent_session": False, "updated_at": ts}


def _tracker_request(method, path, *args, **kwargs):
    if method == "GET" and path.startswith("/enceladus?"):
        return 200, {"items": [_stale_task(f"ENC-TSK-{i:03d}") for i in range(5)]}
    if method == "GET":
        return 200, {"items": []}
    raise AssertionError(f"unexpected tracker call {method} {path}")


class AutoCheckoutCircuitBreakerTest(unittest.TestCase):
    def test_405_trips_breaker_after_single_checkout_call(self):
        with mock.patch.object(checkout_lambda, "_tracker_request", side_effect=_tracker_request) as tr, \
             mock.patch.object(checkout_lambda, "_checkout_task", return_value=(405, {"error": "nope"})) as co, \
             mock.patch.object(checkout_lambda, "_log_task") as lg:
            out = checkout_lambda.handler_auto_checkout({}, None)
        self.assertEqual(co.call_count, 1)
        lg.assert_not_called()
        self.assertEqual(out["checked_out_count"], 0)
        self.assertEqual(out["error_count"], 1)
        # <= 3 list GETs + 1 POST per run
        self.assertLessEqual(tr.call_count + co.call_count, 4)

    def test_other_non_2xx_also_trips_breaker(self):
        with mock.patch.object(checkout_lambda, "_tracker_request", side_effect=_tracker_request), \
             mock.patch.object(checkout_lambda, "_checkout_task", return_value=(500, {})) as co, \
             mock.patch.object(checkout_lambda, "_log_task"):
            checkout_lambda.handler_auto_checkout({}, None)
        self.assertEqual(co.call_count, 1)

    def test_200_continues_loop_as_before(self):
        with mock.patch.object(checkout_lambda, "_tracker_request", side_effect=_tracker_request), \
             mock.patch.object(checkout_lambda, "_checkout_task", return_value=(200, {})) as co, \
             mock.patch.object(checkout_lambda, "_log_task") as lg:
            out = checkout_lambda.handler_auto_checkout({}, None)
        self.assertEqual(co.call_count, 5)
        self.assertEqual(lg.call_count, 5)
        self.assertEqual(out["checked_out_count"], 5)
        self.assertEqual(out["error_count"], 0)


if __name__ == "__main__":
    unittest.main()
