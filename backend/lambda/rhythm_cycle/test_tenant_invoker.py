"""Unit tests for tenant_invoker (ENC-TSK-N18)."""

from __future__ import annotations

import json
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


# --- ENC-TSK-N48 / BRD DOC-44230223DD1C §4.1: did_work / output_count contract ---


class DidWorkStanzaContractTests(unittest.TestCase):
    """write_completion_stanza asserts on OUTPUT, not execution."""

    @mock.patch.object(tenant_invoker, "_s3")
    def test_completed_yields_did_work_true_and_output_count(self, mock_s3):
        tenant_invoker.write_completion_stanza(
            "prefix/alpha.json", "alpha", "completed", {"x": 1}, output_count=7
        )
        body = json.loads(mock_s3.put_object.call_args[1]["Body"])
        self.assertTrue(body["did_work"])
        self.assertEqual(body["output_count"], 7)
        self.assertEqual(body["status"], "completed")

    @mock.patch.object(tenant_invoker, "_s3")
    def test_correct_zero_is_did_work_true_count_zero(self, mock_s3):
        # (b) ran and correctly produced nothing — honest, must NOT be a lying-zero.
        tenant_invoker.write_completion_stanza("p/mc.json", "memory_consolidation", "completed", output_count=0)
        body = json.loads(mock_s3.put_object.call_args[1]["Body"])
        self.assertTrue(body["did_work"])
        self.assertEqual(body["output_count"], 0)

    @mock.patch.object(tenant_invoker, "_s3")
    def test_skipped_yields_did_work_false(self, mock_s3):
        # (c) internally disabled while returning healthy — the lying-zero.
        tenant_invoker.write_completion_stanza("p/cee.json", "corpus_entropy_engine", "skipped")
        body = json.loads(mock_s3.put_object.call_args[1]["Body"])
        self.assertFalse(body["did_work"])
        self.assertIsNone(body["output_count"])

    @mock.patch.object(tenant_invoker, "_s3")
    def test_failed_yields_did_work_false(self, mock_s3):
        tenant_invoker.write_completion_stanza("p/x.json", "x", "failed")
        body = json.loads(mock_s3.put_object.call_args[1]["Body"])
        self.assertFalse(body["did_work"])

    @mock.patch.object(tenant_invoker, "_s3")
    def test_explicit_did_work_override_wins(self, mock_s3):
        tenant_invoker.write_completion_stanza("p/x.json", "x", "completed", did_work=False)
        body = json.loads(mock_s3.put_object.call_args[1]["Body"])
        self.assertFalse(body["did_work"])


class NoWorkDetectionTests(unittest.TestCase):
    """check_silent_tenants reads stanza content three-valued and classifies."""

    @mock.patch.object(tenant_invoker, "_read_stanza")
    @mock.patch.object(tenant_invoker, "_list_stanza_tenants", return_value=["alpha", "beta", "gamma"])
    def test_separates_produced_correct_zero_and_no_work(self, _list, mock_read):
        stanzas = {
            "alpha": {"status": "completed", "did_work": True, "output_count": 5},   # (a)
            "beta": {"status": "completed", "did_work": True, "output_count": 0},    # (b)
            "gamma": {"status": "skipped", "did_work": False, "output_count": None},  # (c)
        }
        mock_read.side_effect = lambda _prefix, name: stanzas[name]
        result = tenant_invoker.check_silent_tenants(
            prior_invoked_names=["alpha", "beta", "gamma"], prior_result_prefix="p", prior_streaks={}
        )
        self.assertEqual(result["no_work_tenants"], ["gamma"])
        self.assertEqual(result["silent_tenants"], [])
        self.assertTrue(result["tenant_output"]["alpha"]["did_work"])
        self.assertEqual(result["tenant_output"]["beta"]["output_count"], 0)
        self.assertFalse(result["tenant_output"]["gamma"]["did_work"])

    @mock.patch.object(tenant_invoker, "_read_stanza", return_value={"status": "completed"})
    @mock.patch.object(tenant_invoker, "_list_stanza_tenants", return_value=["legacy"])
    def test_old_shape_stanza_missing_did_work_is_unknown_not_no_work(self, _list, _read):
        # Backward compat: a stanza that predates the contract must NOT alarm.
        result = tenant_invoker.check_silent_tenants(
            prior_invoked_names=["legacy"], prior_result_prefix="p", prior_streaks={}
        )
        self.assertEqual(result["no_work_tenants"], [])
        self.assertIn("legacy", result["reporting_tenants"])
        self.assertIsNone(result["tenant_output"]["legacy"]["did_work"])

    @mock.patch.object(tenant_invoker, "_read_stanza", return_value=None)
    @mock.patch.object(tenant_invoker, "_list_stanza_tenants", return_value=["x"])
    def test_unreadable_stanza_is_unknown_not_no_work(self, _list, _read):
        result = tenant_invoker.check_silent_tenants(
            prior_invoked_names=["x"], prior_result_prefix="p", prior_streaks={}
        )
        self.assertEqual(result["no_work_tenants"], [])

    @mock.patch.object(tenant_invoker, "_read_stanza")
    @mock.patch.object(tenant_invoker, "_list_stanza_tenants", return_value=[])
    def test_absent_stanza_is_silent_not_no_work_and_not_read(self, _list, mock_read):
        result = tenant_invoker.check_silent_tenants(
            prior_invoked_names=["x"], prior_result_prefix="p", prior_streaks={}
        )
        self.assertEqual(result["silent_tenants"], ["x"])
        self.assertEqual(result["no_work_tenants"], [])
        mock_read.assert_not_called()


class NoWorkMetricTests(unittest.TestCase):
    @mock.patch.object(tenant_invoker, "_cw")
    def test_emits_one_metric_per_no_work_tenant(self, mock_cw):
        tenant_invoker.emit_no_work_metrics("heavy_integrate", ["corpus_entropy_engine"])
        self.assertEqual(mock_cw.put_metric_data.call_count, 1)
        kwargs = mock_cw.put_metric_data.call_args[1]
        self.assertEqual(kwargs["Namespace"], tenant_invoker.CLOUDWATCH_NAMESPACE)
        self.assertEqual(kwargs["MetricData"][0]["MetricName"], "tenant_no_work")
        dims = {d["Name"]: d["Value"] for d in kwargs["MetricData"][0]["Dimensions"]}
        self.assertEqual(dims["Tenant"], "corpus_entropy_engine")

    @mock.patch.object(tenant_invoker, "_cw")
    def test_no_no_work_tenants_emits_nothing(self, mock_cw):
        tenant_invoker.emit_no_work_metrics("heavy_integrate", [])
        mock_cw.put_metric_data.assert_not_called()

    @mock.patch.object(tenant_invoker, "_cw")
    def test_metric_emission_failure_does_not_raise(self, mock_cw):
        mock_cw.put_metric_data.side_effect = Exception("cw down")
        tenant_invoker.emit_no_work_metrics("heavy_integrate", ["x"])  # must not raise


if __name__ == "__main__":
    unittest.main()
