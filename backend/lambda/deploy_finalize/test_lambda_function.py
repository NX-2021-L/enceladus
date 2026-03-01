"""deploy_finalize failure-handling regression tests."""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from unittest.mock import MagicMock, call, patch

_SPEC = importlib.util.spec_from_file_location(
    "deploy_finalize",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
deploy_finalize = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
sys.modules[_SPEC.name] = deploy_finalize
_SPEC.loader.exec_module(deploy_finalize)


class DeployFinalizeFailureHandlingTests(unittest.TestCase):
    def _mock_ddb(self) -> MagicMock:
        ddb = MagicMock()
        ddb.get_item.return_value = {
            "Item": {
                "project_id": {"S": "enceladus"},
                "record_id": {"S": "spec#SPEC-TEST"},
                "included_request_ids": {"L": [{"S": "REQ-1"}, {"S": "REQ-2"}]},
            }
        }
        return ddb

    def test_handle_failure_retryable_resets_pending(self) -> None:
        ddb = self._mock_ddb()
        with patch.object(deploy_finalize, "_get_ddb", return_value=ddb):
            deploy_finalize._handle_failure(
                project_id="enceladus",
                spec_id="SPEC-TEST",
                error_message="CodeBuild FAILED in BUILD: random transient error",
            )

        # 1 spec update + 2 request updates
        self.assertEqual(ddb.update_item.call_count, 3)
        request_calls = ddb.update_item.call_args_list[1:]
        for req_call in request_calls:
            self.assertIn(":pending", req_call.kwargs["ExpressionAttributeValues"])
            self.assertEqual(req_call.kwargs["ExpressionAttributeValues"][":pending"]["S"], "pending")

    def test_handle_failure_non_retryable_marks_failed(self) -> None:
        ddb = self._mock_ddb()
        with patch.object(deploy_finalize, "_get_ddb", return_value=ddb):
            deploy_finalize._handle_failure(
                project_id="enceladus",
                spec_id="SPEC-TEST",
                error_message=(
                    "CodeBuild FAILED in INSTALL: COMMAND_EXECUTION_ERROR: "
                    "python3 $CODEBUILD_SRC_DIR/deploy_build_helper.py fetch-config"
                ),
            )

        self.assertEqual(ddb.update_item.call_count, 3)
        request_calls = ddb.update_item.call_args_list[1:]
        for req_call in request_calls:
            self.assertEqual(req_call.kwargs["ExpressionAttributeValues"][":failed"]["S"], "failed")


if __name__ == "__main__":
    unittest.main()
