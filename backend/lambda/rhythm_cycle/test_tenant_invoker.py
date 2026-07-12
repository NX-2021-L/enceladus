"""Unit tests for tenant_invoker (ENC-TSK-N18)."""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timezone
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import tenant_invoker  # noqa: E402


TENANT_CONFIG = {
    "tenants": {
        "zeta": {
            "beat": "heavy_integrate",
            "enabled": True,
            "function_name": "enceladus-tenant-zeta",
            "order": 20,
        },
        "alpha": {
            "beat": "heavy_integrate",
            "enabled": True,
            "function_name": "enceladus-tenant-alpha",
            "order": 10,
            "expected_output_contract": {"schema_version": 1},
        },
        "killed": {
            "beat": "heavy_integrate",
            "enabled": False,
            "function_name": "enceladus-tenant-killed",
            "order": 5,
        },
        "wrong_beat": {
            "beat": "light_integrate",
            "enabled": True,
            "function_name": "enceladus-tenant-wrong-beat",
            "order": 1,
        },
        "missing_function_name": {
            "beat": "heavy_integrate",
            "enabled": True,
            "order": 1,
        },
    }
}


class ManifestResolutionTests(unittest.TestCase):
    @mock.patch.object(tenant_invoker, "_tenant_config", return_value=TENANT_CONFIG)
    def test_filters_by_beat_and_orders(self, _cfg):
        manifest = tenant_invoker.get_manifest("heavy_integrate")
        names = [t.name for t in manifest]
        # alpha (order 10) before zeta (order 20); wrong_beat excluded (light);
        # killed excluded (enabled=False); missing_function_name excluded.
        self.assertEqual(names, ["alpha", "zeta"])
        self.assertEqual(manifest[0].expected_output_contract, {"schema_version": 1})

    @mock.patch.object(tenant_invoker, "_tenant_config", return_value=TENANT_CONFIG)
    def test_kill_flag_removes_tenant(self, _cfg):
        manifest = tenant_invoker.get_manifest("heavy_integrate")
        names = {t.name for t in manifest}
        self.assertNotIn("killed", names)

    @mock.patch.object(tenant_invoker, "_tenant_config", return_value={})
    def test_empty_config_yields_empty_manifest(self, _cfg):
        self.assertEqual(tenant_invoker.get_manifest("heavy_integrate"), [])

    @mock.patch.object(tenant_invoker, "_tenant_config", return_value=TENANT_CONFIG)
    def test_light_beat_filters_independently(self, _cfg):
        manifest = tenant_invoker.get_manifest("light_integrate")
        self.assertEqual([t.name for t in manifest], ["wrong_beat"])


class InvokeTenantsTests(unittest.TestCase):
    @mock.patch.object(tenant_invoker, "get_manifest")
    @mock.patch.object(tenant_invoker, "_lambda")
    def test_zero_enabled_tenants_makes_no_invoke_calls(self, mock_lambda, mock_manifest):
        mock_manifest.return_value = []
        result = tenant_invoker.invoke_tenants(
            "heavy_integrate", datetime(2026, 7, 12, tzinfo=timezone.utc), "some/predecessor/key.json"
        )
        mock_lambda.invoke.assert_not_called()
        self.assertEqual(result["invoked_tenants"], [])
        self.assertEqual(result["manifest_size"], 0)

    @mock.patch.object(tenant_invoker, "_lambda")
    def test_uniform_payload_shape_and_async_invocation_type(self, mock_lambda):
        manifest = [
            tenant_invoker.TenantDef(
                name="alpha",
                beat="heavy_integrate",
                function_name="enceladus-tenant-alpha",
                order=1,
                expected_output_contract={"schema_version": 1},
            )
        ]
        beat_ts = datetime(2026, 7, 12, 6, 0, 0, tzinfo=timezone.utc)
        result = tenant_invoker.invoke_tenants(
            "heavy_integrate", beat_ts, "rhythm-cycle/decide/latest.json", manifest=manifest
        )
        mock_lambda.invoke.assert_called_once()
        _, kwargs = mock_lambda.invoke.call_args
        self.assertEqual(kwargs["FunctionName"], "enceladus-tenant-alpha")
        self.assertEqual(kwargs["InvocationType"], "Event")
        import json as _json

        payload = _json.loads(kwargs["Payload"])
        for field in (
            "beat_id",
            "beat_type",
            "beat_at",
            "predecessor_artifact_key",
            "expected_output_contract",
            "session_identity",
            "result_key",
        ):
            self.assertIn(field, payload)
        self.assertEqual(payload["predecessor_artifact_key"], "rhythm-cycle/decide/latest.json")
        self.assertEqual(result["invoked_tenants"][0]["name"], "alpha")

    @mock.patch.object(tenant_invoker, "_lambda")
    def test_one_tenant_invoke_failure_does_not_raise_or_block_others(self, mock_lambda):
        mock_lambda.invoke.side_effect = [Exception("boom"), None]
        manifest = [
            tenant_invoker.TenantDef(name="bad", beat="heavy_integrate", function_name="fn-bad", order=1),
            tenant_invoker.TenantDef(name="good", beat="heavy_integrate", function_name="fn-good", order=2),
        ]
        result = tenant_invoker.invoke_tenants(
            "heavy_integrate", datetime.now(timezone.utc), None, manifest=manifest
        )
        invoked_names = [t["name"] for t in result["invoked_tenants"]]
        self.assertEqual(invoked_names, ["good"])


class SilentTenantDetectionTests(unittest.TestCase):
    @mock.patch.object(tenant_invoker, "_list_stanza_tenants", return_value=["alpha"])
    def test_reporting_tenant_resets_streak(self, _list):
        result = tenant_invoker.check_silent_tenants(
            prior_invoked_names=["alpha", "beta"],
            prior_result_prefix="rhythm-cycle/heavy_integrate/tenant-results/x",
            prior_streaks={"alpha": 1, "beta": 1},
        )
        self.assertEqual(result["tenant_silence_streaks"]["alpha"], 0)
        self.assertEqual(result["tenant_silence_streaks"]["beta"], 2)
        self.assertEqual(result["silent_tenants"], ["beta"])
        self.assertEqual(result["reporting_tenants"], ["alpha"])

    @mock.patch.object(tenant_invoker, "_list_stanza_tenants", return_value=[])
    def test_stall_threshold_crossed_at_two_consecutive_silences(self, _list):
        result = tenant_invoker.check_silent_tenants(
            prior_invoked_names=["gamma"],
            prior_result_prefix="rhythm-cycle/heavy_integrate/tenant-results/x",
            prior_streaks={"gamma": 1},
        )
        self.assertEqual(result["tenant_silence_streaks"]["gamma"], 2)
        self.assertEqual(result["stalled_tenants"], ["gamma"])

    @mock.patch.object(tenant_invoker, "_list_stanza_tenants", return_value=[])
    def test_first_silent_window_does_not_yet_stall(self, _list):
        result = tenant_invoker.check_silent_tenants(
            prior_invoked_names=["gamma"], prior_result_prefix="p", prior_streaks={}
        )
        self.assertEqual(result["tenant_silence_streaks"]["gamma"], 1)
        self.assertEqual(result["stalled_tenants"], [])

    def test_no_prior_result_prefix_treats_all_as_silent(self):
        result = tenant_invoker.check_silent_tenants(
            prior_invoked_names=["gamma"], prior_result_prefix=None, prior_streaks={}
        )
        self.assertEqual(result["silent_tenants"], ["gamma"])

    @mock.patch.object(tenant_invoker, "_list_stanza_tenants", return_value=[])
    def test_streaks_drop_tenants_no_longer_invoked(self, _list):
        result = tenant_invoker.check_silent_tenants(
            prior_invoked_names=["gamma"], prior_result_prefix="p", prior_streaks={"retired_tenant": 5, "gamma": 0}
        )
        self.assertNotIn("retired_tenant", result["tenant_silence_streaks"])


class StallMetricTests(unittest.TestCase):
    @mock.patch.object(tenant_invoker, "_cw")
    def test_emits_one_metric_per_stalled_tenant(self, mock_cw):
        tenant_invoker.emit_stall_metrics("heavy_integrate", ["gamma", "delta"])
        self.assertEqual(mock_cw.put_metric_data.call_count, 2)
        _, kwargs = mock_cw.put_metric_data.call_args_list[0]
        self.assertEqual(kwargs["Namespace"], tenant_invoker.CLOUDWATCH_NAMESPACE)
        self.assertEqual(kwargs["MetricData"][0]["MetricName"], "tenant_stall")

    @mock.patch.object(tenant_invoker, "_cw")
    def test_no_stalled_tenants_emits_nothing(self, mock_cw):
        tenant_invoker.emit_stall_metrics("heavy_integrate", [])
        mock_cw.put_metric_data.assert_not_called()

    @mock.patch.object(tenant_invoker, "_cw")
    def test_metric_emission_failure_does_not_raise(self, mock_cw):
        mock_cw.put_metric_data.side_effect = Exception("cw down")
        tenant_invoker.emit_stall_metrics("heavy_integrate", ["gamma"])  # should not raise


class RunTenantOrchestrationTests(unittest.TestCase):
    @mock.patch.object(tenant_invoker, "invoke_tenants")
    @mock.patch.object(tenant_invoker, "emit_stall_metrics")
    @mock.patch.object(tenant_invoker, "check_silent_tenants")
    @mock.patch.object(tenant_invoker, "read_latest")
    def test_wires_predecessor_key_and_prior_streaks_through(
        self, mock_read_latest, mock_check_silent, mock_emit, mock_invoke
    ):
        def read_latest_side_effect(tier):
            if tier == "decide":  # TIER_PREDECESSOR["heavy_integrate"]
                return {"timestamped_key": "rhythm-cycle/decide/2026/07/12/060000.json"}
            if tier == "heavy_integrate":
                return {
                    "tenant_orchestration": {
                        "invoked_tenants": [{"name": "alpha"}],
                        "result_prefix": "rhythm-cycle/heavy_integrate/tenant-results/prior",
                        "tenant_silence_streaks": {"alpha": 1},
                    }
                }
            return None

        mock_read_latest.side_effect = read_latest_side_effect
        mock_check_silent.return_value = {
            "silent_tenants": [],
            "stalled_tenants": [],
            "tenant_silence_streaks": {"alpha": 0},
            "reporting_tenants": ["alpha"],
        }
        mock_invoke.return_value = {"beat_type": "heavy_integrate", "result_prefix": "new", "invoked_tenants": []}

        beat_ts = datetime.now(timezone.utc)
        result = tenant_invoker.run_tenant_orchestration("heavy_integrate", beat_ts)

        mock_check_silent.assert_called_once_with(
            prior_invoked_names=["alpha"],
            prior_result_prefix="rhythm-cycle/heavy_integrate/tenant-results/prior",
            prior_streaks={"alpha": 1},
        )
        mock_invoke.assert_called_once_with(
            "heavy_integrate", beat_ts, "rhythm-cycle/decide/2026/07/12/060000.json"
        )
        self.assertEqual(result["tenant_silence_streaks"], {"alpha": 0})


if __name__ == "__main__":
    unittest.main()
