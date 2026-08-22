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


class DeployFinalizePrefixResolutionO47Tests(unittest.TestCase):
    """ENC-TSK-O47: alias_prefixes-aware resolution in _load_prefix_map()/
    _infer_project_id(). Lighter than the project_utils/server.py suites --
    this Lambda's prefix cache is a flat str->str dict built from a single
    Scan call (no pagination, no dataclass), so one mocked ddb.scan per case
    is enough to exercise the same normalize/skip/collision-surfacing rules.
    Related: ENC-TSK-O47, ENC-TSK-O45, ENC-ISS-538.
    """

    def setUp(self) -> None:
        deploy_finalize._prefix_to_project.clear()
        deploy_finalize._PREFIX_COLLISIONS.clear()

    def tearDown(self) -> None:
        deploy_finalize._prefix_to_project.clear()
        deploy_finalize._PREFIX_COLLISIONS.clear()

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
        with patch.object(deploy_finalize, "_get_ddb", return_value=ddb):
            self.assertEqual(deploy_finalize._infer_project_id("ENC-TSK-001"), "gamma")
        self.assertIn("alias_prefixes", ddb.scan.call_args.kwargs["ProjectionExpression"])

    def test_mint_prefix_resolves_to_same_project_id(self) -> None:
        """(b) The project's new MINT prefix resolves to that same project_id."""
        ddb = MagicMock()
        ddb.scan.return_value = {"Items": [self._row("gamma", prefix="MNT", alias_prefixes=["ENC"])]}
        with patch.object(deploy_finalize, "_get_ddb", return_value=ddb):
            self.assertEqual(deploy_finalize._infer_project_id("MNT-TSK-001"), "gamma")

    def test_unknown_prefix_returns_none(self) -> None:
        """(c) A prefix present in neither `prefix` nor `alias_prefixes` still
        yields no match (this Lambda's resolver returns None, not ValueError --
        callers treat a None project_id as best-effort skip)."""
        ddb = MagicMock()
        ddb.scan.return_value = {"Items": [self._row("gamma", prefix="MNT", alias_prefixes=["ENC"])]}
        with patch.object(deploy_finalize, "_get_ddb", return_value=ddb):
            self.assertIsNone(deploy_finalize._infer_project_id("ZZZ-TSK-001"))

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
        with patch.object(deploy_finalize, "_get_ddb", return_value=ddb), \
                self.assertLogs(deploy_finalize.logger, level="WARNING") as logs:
            resolved = deploy_finalize._infer_project_id("ENC-TSK-001")

        self.assertEqual(resolved, "gamma")
        self.assertEqual(
            deploy_finalize._PREFIX_COLLISIONS.get("ENC"),
            {"mint_project_id": "gamma", "alias_project_id": "legacy-holder"},
        )
        self.assertTrue(any("PREFIX-COLLISION" in msg for msg in logs.output))



if __name__ == "__main__":
    unittest.main()
