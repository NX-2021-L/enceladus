#!/usr/bin/env python3
"""ENC-ISS-519: unit tests for the pure logic in assert_post_deploy_freshness.py
(target-function resolution + LastModified-vs-merge-commit freshness check).
No live git/AWS calls -- see tools/test_compute_affected_targets.py for the
sibling resolver tests this assertion backstops.

Run: python3 -m unittest tools.test_assert_post_deploy_freshness -v
"""
import importlib.util
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent / "assert_post_deploy_freshness.py"
spec = importlib.util.spec_from_file_location("assert_post_deploy_freshness", MODULE_PATH)
apf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(apf)


class ResolveTargetFunctionsTest(unittest.TestCase):
    def test_narrow_scope_maps_affected_dirs_only(self):
        targets = apf.resolve_target_functions(
            full_scope=False,
            affected_functions=["tracker_mutation"],
            function_name_map={"tracker_mutation": "devops-tracker-mutation-api-gamma"},
        )
        self.assertEqual(targets, ["devops-tracker-mutation-api-gamma"])

    def test_dir_absent_from_map_is_skipped(self):
        targets = apf.resolve_target_functions(
            full_scope=False,
            affected_functions=["tracker_mutation", "not_in_map"],
            function_name_map={"tracker_mutation": "devops-tracker-mutation-api-gamma"},
        )
        self.assertEqual(targets, ["devops-tracker-mutation-api-gamma"])

    def test_comma_list_expands_to_multiple_functions(self):
        targets = apf.resolve_target_functions(
            full_scope=False,
            affected_functions=["checkout_service"],
            function_name_map={"checkout_service": "enceladus-checkout-service-gamma, enceladus-checkout-service-auto-gamma"},
        )
        self.assertEqual(
            targets,
            ["enceladus-checkout-service-auto-gamma", "enceladus-checkout-service-gamma"],
        )

    def test_full_scope_uses_all_lambda_dirs(self):
        targets = apf.resolve_target_functions(
            full_scope=True,
            affected_functions=[],
            function_name_map={"a": "fn-a", "b": "fn-b"},
            all_lambda_dirs=["a", "b", "c"],
        )
        self.assertEqual(targets, ["fn-a", "fn-b"])

    def test_empty_map_yields_no_targets(self):
        targets = apf.resolve_target_functions(
            full_scope=False,
            affected_functions=["tracker_mutation"],
            function_name_map={},
        )
        self.assertEqual(targets, [])


class IsFreshTest(unittest.TestCase):
    def test_last_modified_after_merge_is_fresh(self):
        self.assertTrue(apf.is_fresh(
            "2026-07-08T06:15:00.000+0000",
            "2026-07-08T06:00:00+00:00",
        ))

    def test_last_modified_before_merge_is_stale(self):
        # The ENC-ISS-519 silent-skip case: function code predates the merge
        # this run claims to have deployed.
        self.assertFalse(apf.is_fresh(
            "2026-07-07T12:00:00.000+0000",
            "2026-07-08T06:00:00+00:00",
        ))

    def test_equal_timestamps_are_fresh(self):
        self.assertTrue(apf.is_fresh(
            "2026-07-08T06:00:00.000+0000",
            "2026-07-08T06:00:00+00:00",
        ))

    def test_handles_naive_aws_style_offset_without_colon(self):
        # AWS Lambda's LastModified format has no colon in the tz offset
        # ("+0000"); Python's fromisoformat requires one. Must not raise.
        result = apf.is_fresh("2026-07-08T06:00:00.000-0700", "2026-07-08T13:00:00+00:00")
        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()
