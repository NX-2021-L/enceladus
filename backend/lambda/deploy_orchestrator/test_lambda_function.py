"""deploy_orchestrator integration analysis regression tests.

Ensures overlap analysis warns instead of hard-failing so pending deploy
requests are not left unprocessed.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import unittest
import zipfile
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


class DeployOrchestratorHandlerTests(unittest.TestCase):
    def _sqs_record(self, body: dict | None = None, *, message_id: str = "msg-1", raw_body: str | None = None) -> dict:
        payload = raw_body if raw_body is not None else json.dumps(body or {})
        return {"messageId": message_id, "body": payload}

    def test_handler_returns_batch_failure_for_malformed_messages(self) -> None:
        event = {
            "Records": [
                self._sqs_record(raw_body="not-json", message_id="bad-1"),
                self._sqs_record({"project_id": "enceladus"}, message_id="good-1"),
            ]
        }

        with patch.object(deploy_orchestrator, "_orchestrate_deployment") as orchestrate:
            result = deploy_orchestrator.handler(event, None)

        orchestrate.assert_called_once_with("enceladus")
        self.assertEqual(result, {"batchItemFailures": [{"itemIdentifier": "bad-1"}]})

    def test_handler_maps_project_failures_back_to_message_ids(self) -> None:
        event = {
            "Records": [
                self._sqs_record({"project_id": "enceladus"}, message_id="enc-1"),
                self._sqs_record({"project_id": "enceladus"}, message_id="enc-2"),
                self._sqs_record({"project_id": "devops"}, message_id="dev-1"),
            ]
        }

        def _orchestrate(project_id: str) -> None:
            if project_id == "enceladus":
                raise RuntimeError("boom")

        with patch.object(deploy_orchestrator, "_orchestrate_deployment", side_effect=_orchestrate):
            result = deploy_orchestrator.handler(event, None)

        self.assertEqual(
            result,
            {
                "batchItemFailures": [
                    {"itemIdentifier": "enc-1"},
                    {"itemIdentifier": "enc-2"},
                ]
            },
        )


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
        s3.put_object.assert_called_once()

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
        s3.put_object.assert_called_once()

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

    def test_orchestrate_lambda_update_inline_packaging_failure_marks_failed(self) -> None:
        ddb = MagicMock()
        packaging_error = RuntimeError("No files found for source_dir 'feed_publisher' in source archives")
        with patch.object(deploy_orchestrator, "NON_UI_INLINE_LAMBDA_UPDATE", True), patch.object(
            deploy_orchestrator, "_validate_non_ui_requests", return_value=(True, [{"request_id": "REQ-1", "target_arn": "arn:aws:lambda:us-west-2:123456789012:function:devops-feed-publisher"}], [])
        ), patch.object(
            deploy_orchestrator, "_write_spec"
        ), patch.object(
            deploy_orchestrator, "_mark_requests"
        ) as mark_requests, patch.object(
            deploy_orchestrator, "_execute_lambda_update_targets", side_effect=packaging_error
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
        mark_requests.assert_any_call("enceladus", ["REQ-1"], "failed")
        ddb.update_item.assert_called_once()
        expr_values = ddb.update_item.call_args.kwargs["ExpressionAttributeValues"]
        self.assertEqual(expr_values[":failed"]["S"], "failed")


class DeployOrchestratorSourceArchiveFallbackTests(unittest.TestCase):
    def test_resolve_latest_source_archive_falls_back_to_parent_prefix(self) -> None:
        s3 = MagicMock()
        s3.list_objects_v2.side_effect = [
            {"Contents": []},
            {"Contents": [{"Key": "deploy-sources/devops/20260301.zip"}]},
        ]
        with patch.object(
            deploy_orchestrator,
            "_read_project_deploy_config",
            return_value={"source": {"source_s3_bucket": "jreese-net", "source_s3_prefix": "deploy-sources/devops"}},
        ), patch.object(deploy_orchestrator, "_get_s3", return_value=s3):
            bucket, key = deploy_orchestrator._resolve_latest_source_archive(
                "enceladus",
                "jreese-net",
                "deploy-sources/enceladus",
            )
        self.assertEqual(bucket, "jreese-net")
        self.assertEqual(key, "deploy-sources/devops/20260301.zip")

    def test_build_lambda_zip_from_source_tries_multiple_archives_until_marker_found(self) -> None:
        def _zip_bytes(files: dict[str, str]) -> bytes:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
                for name, body in files.items():
                    zf.writestr(name, body)
            return buf.getvalue()

        newest = _zip_bytes({"README.md": "no lambda sources here"})
        older = _zip_bytes(
            {
                "backend/lambda/feed_publisher/lambda_function.py": "print('ok')",
                "backend/lambda/feed_publisher/requirements.txt": "",
            }
        )

        s3 = MagicMock()
        s3.list_objects_v2.return_value = {
            "Contents": [
                {"Key": "deploy-sources/devops/20260301-newest.zip"},
                {"Key": "deploy-sources/devops/20260228-older.zip"},
            ]
        }
        s3.get_object.side_effect = [
            {"Body": io.BytesIO(newest)},
            {"Body": io.BytesIO(older)},
        ]

        with patch.object(
            deploy_orchestrator,
            "_read_project_deploy_config",
            return_value={"source": {"source_s3_bucket": "jreese-net", "source_s3_prefix": "deploy-sources/devops"}},
        ), patch.object(deploy_orchestrator, "_get_s3", return_value=s3):
            package = deploy_orchestrator._build_lambda_zip_from_source(
                "enceladus",
                {"target_arn": "arn:aws:lambda:us-west-2:123456789012:function:devops-feed-publisher"},
            )

        with zipfile.ZipFile(io.BytesIO(package)) as zf:
            self.assertIn("lambda_function.py", zf.namelist())
            self.assertIn("requirements.txt", zf.namelist())
        self.assertEqual(s3.get_object.call_count, 2)


class DeployOrchestratorStructuredErrorTests(unittest.TestCase):
    """Tests for structured JSON error_message in DDB (ENC-TSK-D79)."""

    def _base_request(self) -> dict:
        return {
            "request_id": "REQ-1",
            "change_type": "patch",
            "changes": ["update lambda"],
            "related_record_ids": ["ENC-TSK-001"],
        }

    def test_error_message_is_structured_json(self) -> None:
        """Error message stored in DDB is structured JSON with service, failure_type, message, retryable."""
        ddb = MagicMock()
        with patch.object(deploy_orchestrator, "NON_UI_INLINE_LAMBDA_UPDATE", True), patch.object(
            deploy_orchestrator, "_validate_non_ui_requests", return_value=(True, [{"request_id": "REQ-1", "target_arn": "arn:aws:lambda:us-west-2:123456789012:function:devops-feed-publisher"}], [])
        ), patch.object(
            deploy_orchestrator, "_write_spec"
        ), patch.object(
            deploy_orchestrator, "_mark_requests"
        ), patch.object(
            deploy_orchestrator, "_execute_lambda_update_targets", side_effect=RuntimeError("function not found")
        ), patch.object(
            deploy_orchestrator, "_get_ddb", return_value=ddb
        ):
            with self.assertRaises(RuntimeError):
                deploy_orchestrator._orchestrate_typed_batch(
                    "enceladus",
                    "lambda_update",
                    [self._base_request()],
                )

        ddb.update_item.assert_called_once()
        expr_values = ddb.update_item.call_args.kwargs["ExpressionAttributeValues"]
        err_raw = expr_values[":err"]["S"]
        err = json.loads(err_raw)
        self.assertEqual(err["service"], "deploy_orchestrator")
        self.assertEqual(err["failure_type"], "inline_lambda_update")
        self.assertIn("function not found", err["message"])
        self.assertIsInstance(err["retryable"], bool)
        self.assertIsInstance(err["next_steps"], list)
        self.assertIn("spec_id", err)


class DeployOrchestratorPrefixResolutionO47Tests(unittest.TestCase):
    """ENC-TSK-O47: alias_prefixes-aware resolution in _load_prefix_map()/
    _infer_project_id(). Lighter than the project_utils/server.py suites --
    this Lambda's prefix cache is a flat str->str dict built from a single
    Scan call (no pagination, no dataclass), so one mocked ddb.scan per case
    is enough to exercise the same normalize/skip/collision-surfacing rules.
    Related: ENC-TSK-O47, ENC-TSK-O45, ENC-ISS-538.
    """

    def setUp(self) -> None:
        deploy_orchestrator._prefix_to_project.clear()
        deploy_orchestrator._PREFIX_COLLISIONS.clear()

    def tearDown(self) -> None:
        deploy_orchestrator._prefix_to_project.clear()
        deploy_orchestrator._PREFIX_COLLISIONS.clear()

    @staticmethod
    def _row(project_id, prefix=None, alias_prefixes=None):
        item = {"project_id": {"S": project_id}}
        if prefix is not None:
            item["prefix"] = {"S": prefix}
        if alias_prefixes is not None:
            item["alias_prefixes"] = {"L": [{"S": a} for a in alias_prefixes]}
        return item

    def test_alias_prefix_resolves_to_project_id(self) -> None:
        """(a) A legacy alias_prefixes entry resolves to the owning project_id,
        and alias_prefixes is actually projected (not just prefix)."""
        ddb = MagicMock()
        ddb.scan.return_value = {"Items": [self._row("gamma", prefix="MNT", alias_prefixes=["enc"])]}
        with patch.object(deploy_orchestrator, "_get_ddb", return_value=ddb):
            self.assertEqual(deploy_orchestrator._infer_project_id("ENC-TSK-001"), "gamma")
        self.assertIn("alias_prefixes", ddb.scan.call_args.kwargs["ProjectionExpression"])

    def test_mint_prefix_resolves_to_same_project_id(self) -> None:
        """(b) The project's new MINT prefix resolves to that same project_id."""
        ddb = MagicMock()
        ddb.scan.return_value = {"Items": [self._row("gamma", prefix="MNT", alias_prefixes=["ENC"])]}
        with patch.object(deploy_orchestrator, "_get_ddb", return_value=ddb):
            self.assertEqual(deploy_orchestrator._infer_project_id("MNT-TSK-001"), "gamma")

    def test_unknown_prefix_returns_none(self) -> None:
        """(c) A prefix present in neither `prefix` nor `alias_prefixes` still
        yields no match (this Lambda's resolver returns None, not ValueError --
        callers treat a None project_id as best-effort skip)."""
        ddb = MagicMock()
        ddb.scan.return_value = {"Items": [self._row("gamma", prefix="MNT", alias_prefixes=["ENC"])]}
        with patch.object(deploy_orchestrator, "_get_ddb", return_value=ddb):
            self.assertIsNone(deploy_orchestrator._infer_project_id("ZZZ-TSK-001"))

    def test_mint_vs_alias_collision_resolves_to_mint_and_is_surfaced(self) -> None:
        """(d) MINT always wins a mint-vs-alias collision, and the collision is
        never silently resolved: it is logged and recorded in _PREFIX_COLLISIONS."""
        ddb = MagicMock()
        ddb.scan.return_value = {
            "Items": [
                self._row("legacy-holder", prefix="OTH", alias_prefixes=["ENC"]),
                self._row("gamma", prefix="ENC", alias_prefixes=[]),
            ]
        }
        with patch.object(deploy_orchestrator, "_get_ddb", return_value=ddb), \
                self.assertLogs(deploy_orchestrator.logger, level="WARNING") as logs:
            resolved = deploy_orchestrator._infer_project_id("ENC-TSK-001")

        self.assertEqual(resolved, "gamma")
        self.assertEqual(
            deploy_orchestrator._PREFIX_COLLISIONS.get("ENC"),
            {"mint_project_id": "gamma", "alias_project_id": "legacy-holder"},
        )
        self.assertTrue(any("PREFIX-COLLISION" in msg for msg in logs.output))



if __name__ == "__main__":
    unittest.main()
