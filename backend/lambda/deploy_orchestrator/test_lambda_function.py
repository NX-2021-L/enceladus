"""deploy_orchestrator integration analysis regression tests.

Ensures overlap analysis warns instead of hard-failing so pending deploy
requests are not left unprocessed.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

_SPEC = importlib.util.spec_from_file_location(
    "deploy_orchestrator",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
deploy_orchestrator = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
sys.modules[_SPEC.name] = deploy_orchestrator
_SPEC.loader.exec_module(deploy_orchestrator)


class DeployOrchestratorIntegrationAnalysisTests(unittest.TestCase):
    def test_analyze_integration_passes_without_overlaps(self) -> None:
        requests = [
            {"request_id": "REQ-1", "files_changed": ["frontend/ui/src/app.tsx"], "related_record_ids": []},
            {"request_id": "REQ-2", "files_changed": ["frontend/ui/src/hooks/useFeed.ts"], "related_record_ids": []},
        ]
        result = deploy_orchestrator._analyze_integration(requests)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["file_overlaps"], [])
        self.assertEqual(result["warnings"], [])

    def test_analyze_integration_warns_on_regular_file_overlap(self) -> None:
        requests = [
            {"request_id": "REQ-1", "files_changed": ["frontend/ui/src/app.tsx"], "related_record_ids": []},
            {"request_id": "REQ-2", "files_changed": ["frontend/ui/src/app.tsx"], "related_record_ids": []},
        ]
        result = deploy_orchestrator._analyze_integration(requests)
        self.assertEqual(result["status"], "warning")
        self.assertTrue(any("frontend/ui/src/app.tsx" in msg for msg in result["warnings"]))

    def test_analyze_integration_warns_not_fails_for_version_overlap(self) -> None:
        requests = [
            {"request_id": "REQ-1", "files_changed": ["frontend/ui/src/lib/version.ts"], "related_record_ids": []},
            {"request_id": "REQ-2", "files_changed": ["frontend/ui/src/lib/version.ts"], "related_record_ids": []},
        ]
        result = deploy_orchestrator._analyze_integration(requests)
        self.assertEqual(result["status"], "warning")
        self.assertTrue(any("version.ts" in msg for msg in result["warnings"]))


class DeployOrchestratorFallbackTests(unittest.TestCase):
    def test_read_deploy_config_missing_uses_synthesized_default(self) -> None:
        s3 = MagicMock()
        s3.get_object.side_effect = ClientError(
            {"Error": {"Code": "NoSuchKey", "Message": "not found"}},
            "GetObject",
        )
        with patch.object(deploy_orchestrator, "_get_s3", return_value=s3), patch.object(
            deploy_orchestrator, "_read_project_deploy_config", return_value=None
        ):
            cfg = deploy_orchestrator._read_deploy_config("enceladus")
        self.assertEqual(cfg["source"]["source_s3_bucket"], deploy_orchestrator.CONFIG_BUCKET)
        self.assertEqual(cfg["source"]["source_s3_prefix"], "deploy-sources/enceladus")
        self.assertTrue(cfg["build"]["version_file"])

    def test_read_deploy_config_missing_uses_project_metadata_fallback(self) -> None:
        s3 = MagicMock()
        s3.get_object.side_effect = ClientError(
            {"Error": {"Code": "NoSuchKey", "Message": "not found"}},
            "GetObject",
        )
        fallback = {
            "source": {"source_s3_bucket": "custom-bucket", "source_s3_prefix": "custom-prefix"},
            "build": {"version_file": "frontend/ui/src/lib/version.ts"},
        }
        with patch.object(deploy_orchestrator, "_get_s3", return_value=s3), patch.object(
            deploy_orchestrator, "_read_project_deploy_config", return_value=fallback
        ):
            cfg = deploy_orchestrator._read_deploy_config("enceladus")
        self.assertEqual(cfg, fallback)

    def test_read_project_deploy_config_defaults_source_prefix_to_parent(self) -> None:
        ddb = MagicMock()
        ddb.get_item.return_value = {
            "Item": {
                "project_id": {"S": "enceladus"},
                "parent": {"S": "devops"},
            }
        }
        with patch.object(deploy_orchestrator, "_get_ddb", return_value=ddb):
            cfg = deploy_orchestrator._read_project_deploy_config("enceladus")
        assert cfg is not None
        self.assertEqual(cfg["source"]["source_s3_prefix"], "deploy-sources/devops")


class DeployOrchestratorNonUiInlineExecutionTests(unittest.TestCase):
    def _base_request(self) -> dict:
        return {
            "request_id": "REQ-1",
            "change_type": "patch",
            "changes": ["update lambda"],
            "related_record_ids": ["ENC-TSK-001"],
        }

    def test_orchestrate_lambda_update_inline_success_marks_spec_deployed(self) -> None:
        ddb = MagicMock()
        with patch.object(deploy_orchestrator, "NON_UI_INLINE_LAMBDA_UPDATE", True), patch.object(
            deploy_orchestrator, "_validate_non_ui_requests", return_value=(True, [{"request_id": "REQ-1", "target_arn": "arn:aws:lambda:us-west-2:123456789012:function:devops-feed-publisher"}], [])
        ), patch.object(
            deploy_orchestrator, "_write_spec"
        ) as write_spec, patch.object(
            deploy_orchestrator, "_mark_requests"
        ) as mark_requests, patch.object(
            deploy_orchestrator, "_execute_lambda_update_targets", return_value=[{"request_id": "REQ-1", "status": "Successful"}]
        ), patch.object(
            deploy_orchestrator, "_get_ddb", return_value=ddb
        ):
            deploy_orchestrator._orchestrate_typed_batch(
                "enceladus",
                "lambda_update",
                [self._base_request()],
            )

        write_spec.assert_called_once()
        mark_requests.assert_called_once_with("enceladus", ["REQ-1"], "included", unittest.mock.ANY)
        ddb.update_item.assert_called_once()
        expr_values = ddb.update_item.call_args.kwargs["ExpressionAttributeValues"]
        self.assertEqual(expr_values[":deployed"]["S"], "deployed")

    def test_orchestrate_lambda_update_inline_failure_resets_pending(self) -> None:
        ddb = MagicMock()
        with patch.object(deploy_orchestrator, "NON_UI_INLINE_LAMBDA_UPDATE", True), patch.object(
            deploy_orchestrator, "_validate_non_ui_requests", return_value=(True, [{"request_id": "REQ-1", "target_arn": "arn:aws:lambda:us-west-2:123456789012:function:devops-feed-publisher"}], [])
        ), patch.object(
            deploy_orchestrator, "_write_spec"
        ), patch.object(
            deploy_orchestrator, "_mark_requests"
        ) as mark_requests, patch.object(
            deploy_orchestrator, "_execute_lambda_update_targets", side_effect=RuntimeError("boom")
        ), patch.object(
            deploy_orchestrator, "_get_ddb", return_value=ddb
        ):
            with self.assertRaises(RuntimeError):
                deploy_orchestrator._orchestrate_typed_batch(
                    "enceladus",
                    "lambda_update",
                    [self._base_request()],
                )

        self.assertEqual(mark_requests.call_count, 2)
        mark_requests.assert_any_call("enceladus", ["REQ-1"], "included", unittest.mock.ANY)
        mark_requests.assert_any_call("enceladus", ["REQ-1"], "pending")
        ddb.update_item.assert_called_once()
        expr_values = ddb.update_item.call_args.kwargs["ExpressionAttributeValues"]
        self.assertEqual(expr_values[":failed"]["S"], "failed")


if __name__ == "__main__":
    unittest.main()
