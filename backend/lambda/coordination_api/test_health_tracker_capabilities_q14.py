"""ENC-TSK-Q14-0E (O2.5/D9): _handle_health carries tracker_capabilities.

GET /api/v1/health (backend/lambda/coordination_api/lambda_function.py
_handle_health) is the canonical source -- tools/enceladus-mcp-server's
connection_health() merges this response as-is (_health_api_request()), and
ELR reads /api/v1/health directly, so asserting the block here covers both
downstream readers without touching either of them.
"""
import importlib.util
import json
import pathlib
import sys
import unittest
from unittest.mock import MagicMock, patch

MODULE_PATH = pathlib.Path(__file__).with_name("lambda_function.py")
SPEC = importlib.util.spec_from_file_location("coordination_lambda_health_q14", MODULE_PATH)
coordination_lambda = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = coordination_lambda
SPEC.loader.exec_module(coordination_lambda)


class TestHealthTrackerCapabilities(unittest.TestCase):
    def test_health_response_carries_tracker_capabilities_block(self):
        fake_ddb = MagicMock()
        fake_s3 = MagicMock()
        with patch.object(coordination_lambda, "_get_ddb", return_value=fake_ddb), \
             patch.object(coordination_lambda, "_get_s3", return_value=fake_s3), \
             patch.object(coordination_lambda, "_compute_governance_hash_local", return_value="deadbeef"):
            resp = coordination_lambda._handle_health()

        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertIn("tracker_capabilities", body)
        self.assertEqual(
            body["tracker_capabilities"],
            {"census": True, "list_cursor_v2": True},
        )

    def test_tracker_capabilities_present_even_when_dynamodb_unreachable(self):
        # tracker_capabilities describes what the API supports, not live
        # connectivity -- it must not disappear just because the
        # DynamoDB/S3 reachability probes in the same handler fail.
        with patch.object(coordination_lambda, "_get_ddb", side_effect=RuntimeError("down")), \
             patch.object(coordination_lambda, "_get_s3", side_effect=RuntimeError("down")), \
             patch.object(coordination_lambda, "_compute_governance_hash_local", side_effect=RuntimeError("down")):
            resp = coordination_lambda._handle_health()

        body = json.loads(resp["body"])
        self.assertEqual(body["dynamodb"], "unreachable: down")
        self.assertIn("tracker_capabilities", body)
        self.assertTrue(body["tracker_capabilities"]["census"])
        self.assertTrue(body["tracker_capabilities"]["list_cursor_v2"])


if __name__ == "__main__":
    unittest.main()
