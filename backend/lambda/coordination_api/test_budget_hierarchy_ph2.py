"""Unit tests for the Budget Hierarchy Controller Phase 2 (ENC-FTR-083 / ENC-TSK-I87).

Covers the Phase 2 acceptance criteria:
  * AC-4: five-level alert ladder (NORMAL/NOTICE/WARNING/CRITICAL/FRAGMENTED at
    50/70/85/95/100%) — corpus utilization of 0.72 classifies as NOTICE and
    triggers exactly one SNS publish carrying that level.
  * AC-5: two consecutive wave-close budget vectors whose infinity-norm delta is
    0.12 (> 0.1) trigger a recalibration log entry.
  * AC-6: a forced mid-wave cache-miss produces a wave-budget-extension record
    written to the enceladus-drift-telemetry sink (DynamoDB put_item).
  * AC-7 / ENC-ISS-265: corpus token-usage telemetry is emitted as the
    Enceladus/BudgetController/CorpusTokenUsage CloudWatch metric, measured
    against the PPR-informed baseline.

Pure-stdlib unittest with injected fake AWS clients so it runs under both
``python -m unittest`` and pytest with no boto3 / AWS dependency.
"""
import json
import logging
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import budget_hierarchy as bhc  # noqa: E402


class _CapturingLogger:
    """Minimal logger stand-in that records formatted messages by level."""

    def __init__(self):
        self.info_records = []
        self.warning_records = []
        self.debug_records = []

    def _fmt(self, args):
        if not args:
            return ""
        msg = args[0]
        params = args[1:]
        try:
            return msg % params if params else msg
        except (TypeError, ValueError):
            return " ".join(str(a) for a in args)

    def info(self, *args, **kwargs):
        self.info_records.append(self._fmt(args))

    def warning(self, *args, **kwargs):
        self.warning_records.append(self._fmt(args))

    def debug(self, *args, **kwargs):
        self.debug_records.append(self._fmt(args))


class _FakeSns:
    def __init__(self):
        self.calls = []

    def publish(self, **kwargs):
        self.calls.append(kwargs)
        return {"MessageId": "msg-test-1"}


class _FakeCloudWatch:
    def __init__(self):
        self.calls = []

    def put_metric_data(self, **kwargs):
        self.calls.append(kwargs)
        return {}


class _FakeDynamo:
    def __init__(self):
        self.items = []

    def put_item(self, **kwargs):
        self.items.append(kwargs)
        return {}


class TestAlertLadder(unittest.TestCase):
    """AC-4: five-level alert ladder + SNS publish."""

    def test_ladder_has_five_canonical_levels(self):
        names = [name for name, _floor in bhc.ALERT_LADDER]
        self.assertEqual(names, ["NORMAL", "NOTICE", "WARNING", "CRITICAL", "FRAGMENTED"])
        floors = [floor for _name, floor in bhc.ALERT_LADDER]
        self.assertEqual(floors, [0.50, 0.70, 0.85, 0.95, 1.00])

    def test_classify_levels_at_each_boundary(self):
        self.assertIsNone(bhc.classify_alert_level(0.49))
        self.assertEqual(bhc.classify_alert_level(0.50)["level"], "NORMAL")
        self.assertEqual(bhc.classify_alert_level(0.72)["level"], "NOTICE")
        self.assertEqual(bhc.classify_alert_level(0.85)["level"], "WARNING")
        self.assertEqual(bhc.classify_alert_level(0.96)["level"], "CRITICAL")
        self.assertEqual(bhc.classify_alert_level(1.0)["level"], "FRAGMENTED")
        self.assertEqual(bhc.classify_alert_level(1.5)["level"], "FRAGMENTED")

    def test_corpus_at_72pct_classifies_notice(self):
        budgets = {"session": 200_000, "wave": 50_000, "project": 500_000, "corpus": 2_000_000}
        used = int(0.72 * budgets["corpus"])  # 1_440_000
        util = bhc.corpus_utilization(used, budgets)
        self.assertAlmostEqual(util, 0.72, places=6)
        level = bhc.classify_alert_level(util)
        self.assertEqual(level["level"], "NOTICE")
        self.assertEqual(level["rank"], bhc.ALERT_LEVELS["NOTICE"])

    def test_notice_triggers_single_sns_publish_with_level(self):
        budgets = {"session": 200_000, "wave": 50_000, "project": 500_000, "corpus": 2_000_000}
        used = 1_440_000  # 72%
        logger = _CapturingLogger()
        sns = _FakeSns()
        level = bhc.classify_alert_level(bhc.corpus_utilization(used, budgets))
        result = bhc.publish_corpus_alert(
            level,
            used_tokens=used,
            budgets=budgets,
            logger=logger,
            sns_client=sns,
            topic_arn="arn:aws:sns:us-west-2:111122223333:enceladus-budget-alerts",
        )
        self.assertTrue(result["published"])
        self.assertEqual(len(sns.calls), 1)
        published = json.loads(sns.calls[0]["Message"])
        self.assertEqual(published["level"], "NOTICE")
        self.assertEqual(published["event_type"], "budget.corpus_alert")
        # AC-4 CloudWatch-Logs evidence line present.
        self.assertTrue(any("[BUDGET][ALERT]" in r for r in logger.info_records))

    def test_normal_level_logs_but_does_not_publish(self):
        budgets = {"session": 200_000, "wave": 50_000, "project": 500_000, "corpus": 2_000_000}
        used = 1_200_000  # 60% -> NORMAL
        logger = _CapturingLogger()
        sns = _FakeSns()
        level = bhc.classify_alert_level(bhc.corpus_utilization(used, budgets))
        self.assertEqual(level["level"], "NORMAL")
        result = bhc.publish_corpus_alert(
            level, used_tokens=used, budgets=budgets, logger=logger,
            sns_client=sns, topic_arn="arn:aws:sns:us-west-2:111122223333:t",
        )
        self.assertFalse(result["published"])
        self.assertEqual(len(sns.calls), 0)

    def test_publish_failure_is_swallowed(self):
        class _BoomSns:
            def publish(self, **kwargs):
                raise RuntimeError("SNS down")

        budgets = {"session": 200_000, "wave": 50_000, "project": 500_000, "corpus": 2_000_000}
        logger = _CapturingLogger()
        level = bhc.classify_alert_level(0.9)  # WARNING
        result = bhc.publish_corpus_alert(
            level, used_tokens=1_800_000, budgets=budgets, logger=logger,
            sns_client=_BoomSns(), topic_arn="arn:aws:sns:us-west-2:111122223333:t",
        )
        self.assertFalse(result["published"])
        self.assertTrue(any("SNS publish failed" in r for r in logger.warning_records))


class TestDriftMonitor(unittest.TestCase):
    """AC-5: wave-close drift monitor triggers recalibration at inf-norm > 0.1."""

    def test_inf_norm_delta(self):
        self.assertAlmostEqual(bhc.inf_norm_delta([0.1, 0.2, 0.3], [0.1, 0.2, 0.42]), 0.12, places=6)

    def test_consecutive_drift_of_0_12_triggers_recalibration(self):
        logger = _CapturingLogger()
        monitor = bhc.WaveBudgetDriftMonitor(logger=logger)
        first = monitor.observe_wave_close([0.40, 0.50, 0.30, 0.60], wave_id="w1")
        self.assertFalse(first["recalibrate"])
        self.assertIsNone(first["drift"])
        # Second vector differs by exactly 0.12 in the infinity norm.
        second = monitor.observe_wave_close([0.40, 0.62, 0.30, 0.60], wave_id="w2")
        self.assertAlmostEqual(second["drift"], 0.12, places=6)
        self.assertTrue(second["recalibrate"])
        # AC-5 recalibration log entry asserted.
        self.assertTrue(
            any("[BUDGET][DRIFT] recalibration triggered" in r for r in logger.warning_records),
            "expected a recalibration log entry",
        )

    def test_drift_at_threshold_does_not_trigger(self):
        logger = _CapturingLogger()
        monitor = bhc.WaveBudgetDriftMonitor(logger=logger)
        monitor.observe_wave_close([0.10, 0.10, 0.10, 0.10], wave_id="w1")
        result = monitor.observe_wave_close([0.20, 0.10, 0.10, 0.10], wave_id="w2")
        # Exactly 0.10 is NOT strictly greater than the 0.10 threshold.
        self.assertAlmostEqual(result["drift"], 0.10, places=6)
        self.assertFalse(result["recalibrate"])
        self.assertFalse(
            any("[BUDGET][DRIFT] recalibration triggered" in r for r in logger.warning_records)
        )

    def test_small_drift_no_recalibration(self):
        logger = _CapturingLogger()
        monitor = bhc.WaveBudgetDriftMonitor(logger=logger)
        monitor.observe_wave_close([0.40, 0.50, 0.30, 0.60])
        result = monitor.observe_wave_close([0.41, 0.51, 0.31, 0.61])
        self.assertLess(result["drift"], bhc.DRIFT_INF_NORM_THRESHOLD)
        self.assertFalse(result["recalibrate"])


class TestEmergencyAdmission(unittest.TestCase):
    """AC-6: emergency mid-wave admission writes a wave-budget-extension record."""

    def test_cache_miss_overflow_grants_extension_and_persists(self):
        logger = _CapturingLogger()
        dynamo = _FakeDynamo()
        record = bhc.emergency_wave_admission(
            logger=logger,
            session_id="ENC-SES-TEST",
            wave_id="wave-7",
            requested_tokens=8_000,
            wave_used_tokens=48_000,
            wave_budget_tokens=50_000,
            reason="cache_miss",
            dynamodb_client=dynamo,
            table_name="enceladus-drift-telemetry",
        )
        # 48k + 8k = 56k projected vs 50k budget -> 6k overflow; extension >= overflow.
        self.assertEqual(record["overflow_tokens"], 6_000)
        self.assertGreaterEqual(record["granted_extension_tokens"], 6_000)
        self.assertEqual(
            record["extended_wave_budget_tokens"],
            50_000 + record["granted_extension_tokens"],
        )
        self.assertEqual(record["record_type"], "wave_budget_extension")
        self.assertTrue(record["admitted"])
        self.assertTrue(record["persisted"])
        # One DynamoDB write to the drift-telemetry sink.
        self.assertEqual(len(dynamo.items), 1)
        self.assertEqual(dynamo.items[0]["TableName"], "enceladus-drift-telemetry")
        item = dynamo.items[0]["Item"]
        self.assertEqual(item["record_type"]["S"], "wave_budget_extension")
        self.assertEqual(item["wave_id"]["S"], "wave-7")
        self.assertIn("telemetry_id", item)

    def test_degrades_to_log_when_dynamo_write_fails(self):
        class _BoomDynamo:
            def put_item(self, **kwargs):
                raise RuntimeError("table missing")

        logger = _CapturingLogger()
        record = bhc.emergency_wave_admission(
            logger=logger,
            session_id="ENC-SES-TEST",
            wave_id="wave-9",
            requested_tokens=5_000,
            wave_used_tokens=49_000,
            wave_budget_tokens=50_000,
            dynamodb_client=_BoomDynamo(),
            table_name="enceladus-drift-telemetry",
        )
        self.assertFalse(record["persisted"])
        # The extension record is still returned and logged (degraded sink).
        self.assertTrue(record["admitted"])
        self.assertTrue(
            any("[BUDGET][EMERGENCY-ADMISSION]" in r for r in logger.warning_records)
        )


class TestCorpusTelemetry(unittest.TestCase):
    """AC-7 / ENC-ISS-265: corpus token-usage CloudWatch metric vs PPR baseline."""

    def test_emits_corpus_token_usage_metric(self):
        logger = _CapturingLogger()
        cw = _FakeCloudWatch()
        budgets = {"session": 200_000, "wave": 50_000, "project": 500_000, "corpus": 2_000_000}
        result = bhc.emit_corpus_token_usage_metric(
            1_440_000,
            logger=logger,
            budgets=budgets,
            ppr_baseline_tokens=1_200_000,
            cloudwatch_client=cw,
            project_id="enceladus",
        )
        self.assertTrue(result["emitted"])
        self.assertEqual(len(cw.calls), 1)
        call = cw.calls[0]
        self.assertEqual(call["Namespace"], "Enceladus/BudgetController")
        metric_names = {m["MetricName"] for m in call["MetricData"]}
        self.assertIn("CorpusTokenUsage", metric_names)
        # PPR-informed baseline ratio also emitted (1_440_000 / 1_200_000 = 1.2).
        self.assertIn("CorpusTokenUsageVsBaseline", metric_names)
        self.assertAlmostEqual(result["used_vs_ppr_baseline"], 1.2, places=6)
        self.assertTrue(
            any("[BUDGET][CORPUS-TELEMETRY]" in r for r in logger.info_records)
        )

    def test_metric_without_baseline_emits_single_series(self):
        logger = _CapturingLogger()
        cw = _FakeCloudWatch()
        budgets = {"session": 200_000, "wave": 50_000, "project": 500_000, "corpus": 2_000_000}
        result = bhc.emit_corpus_token_usage_metric(
            1_000_000, logger=logger, budgets=budgets, cloudwatch_client=cw,
        )
        self.assertTrue(result["emitted"])
        metric_names = {m["MetricName"] for m in cw.calls[0]["MetricData"]}
        self.assertEqual(metric_names, {"CorpusTokenUsage"})
        self.assertIsNone(result["used_vs_ppr_baseline"])


class TestEvaluateCorpusBudget(unittest.TestCase):
    """The end-to-end orchestrator wired into session-init."""

    def test_returns_none_without_usage_signal(self):
        logger = _CapturingLogger()
        # Ensure no env signal leaks in.
        os.environ.pop("BUDGET_CORPUS_USED_TOKENS", None)
        result = bhc.evaluate_corpus_budget(logger, sns_client=_FakeSns(), cloudwatch_client=_FakeCloudWatch())
        self.assertIsNone(result)

    def test_full_path_classifies_publishes_and_emits(self):
        logger = _CapturingLogger()
        sns = _FakeSns()
        cw = _FakeCloudWatch()
        result = bhc.evaluate_corpus_budget(
            logger,
            used_tokens=1_440_000,  # 72% of 2M default corpus budget
            sns_client=sns,
            cloudwatch_client=cw,
            topic_arn="arn:aws:sns:us-west-2:111122223333:enceladus-budget-alerts",
            ppr_baseline_tokens=1_200_000,
            project_id="enceladus",
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["level"]["level"], "NOTICE")
        self.assertTrue(result["alert"]["published"])
        self.assertEqual(len(sns.calls), 1)
        self.assertEqual(len(cw.calls), 1)

    def test_reads_used_tokens_from_env(self):
        logger = _CapturingLogger()
        sns = _FakeSns()
        cw = _FakeCloudWatch()
        os.environ["BUDGET_CORPUS_USED_TOKENS"] = "1440000"
        try:
            result = bhc.evaluate_corpus_budget(
                logger, sns_client=sns, cloudwatch_client=cw,
                topic_arn="arn:aws:sns:us-west-2:111122223333:t",
            )
        finally:
            del os.environ["BUDGET_CORPUS_USED_TOKENS"]
        self.assertIsNotNone(result)
        self.assertEqual(result["level"]["level"], "NOTICE")


class TestSpuriousAttractorAlert(unittest.TestCase):
    """ENC-TSK-I91 (ENC-FTR-105 AC-7): spurious-attractor NOTICE rung.

    SNS publish fires on threshold breach (> 0.15) and does not fire below it,
    via the exact same SNS-publish idiom as the AC-4 alert ladder.
    """

    def test_threshold_is_015(self):
        self.assertAlmostEqual(bhc.SPURIOUS_ATTRACTOR_NOTICE_THRESHOLD, 0.15)

    def test_none_rate_is_a_noop(self):
        logger = _CapturingLogger()
        sns = _FakeSns()
        result = bhc.evaluate_spurious_attractor_alert(
            None, logger=logger, sns_client=sns,
            topic_arn="arn:aws:sns:us-west-2:111122223333:t",
        )
        self.assertIsNone(result)
        self.assertEqual(len(sns.calls), 0)

    def test_above_threshold_publishes_notice(self):
        logger = _CapturingLogger()
        sns = _FakeSns()
        result = bhc.evaluate_spurious_attractor_alert(
            0.20, logger=logger, sns_client=sns,
            topic_arn="arn:aws:sns:us-west-2:111122223333:enceladus-budget-alerts",
            project_id="enceladus", wave_id="wave-9",
        )
        self.assertTrue(result["published"])
        self.assertEqual(len(sns.calls), 1)
        published = json.loads(sns.calls[0]["Message"])
        self.assertEqual(published["level"], "NOTICE")
        self.assertEqual(published["event_type"], "budget.spurious_attractor_alert")
        self.assertAlmostEqual(published["spurious_attractor_rate"], 0.20)
        self.assertEqual(published["wave_id"], "wave-9")
        # AC-7 CloudWatch-Logs evidence line present (same convention as AC-4).
        self.assertTrue(any("[BUDGET][ALERT]" in r for r in logger.info_records))

    def test_at_threshold_does_not_publish(self):
        """Strict greater-than: exactly 0.15 must NOT publish."""
        logger = _CapturingLogger()
        sns = _FakeSns()
        result = bhc.evaluate_spurious_attractor_alert(
            0.15, logger=logger, sns_client=sns,
            topic_arn="arn:aws:sns:us-west-2:111122223333:t",
        )
        self.assertFalse(result["published"])
        self.assertEqual(len(sns.calls), 0)

    def test_below_threshold_does_not_publish(self):
        logger = _CapturingLogger()
        sns = _FakeSns()
        result = bhc.evaluate_spurious_attractor_alert(
            0.05, logger=logger, sns_client=sns,
            topic_arn="arn:aws:sns:us-west-2:111122223333:t",
        )
        self.assertFalse(result["published"])
        self.assertEqual(len(sns.calls), 0)
        self.assertTrue(any("[BUDGET][ALERT]" in r for r in logger.info_records))

    def test_no_topic_configured_logs_only(self):
        logger = _CapturingLogger()
        os.environ.pop("BUDGET_ALERT_SNS_TOPIC_ARN", None)
        os.environ.pop("DEAD_LETTER_SNS_TOPIC_ARN", None)
        result = bhc.evaluate_spurious_attractor_alert(0.5, logger=logger, sns_client=_FakeSns())
        self.assertFalse(result["published"])

    def test_publish_failure_is_swallowed(self):
        class _BoomSns:
            def publish(self, **kwargs):
                raise RuntimeError("SNS down")

        logger = _CapturingLogger()
        result = bhc.evaluate_spurious_attractor_alert(
            0.9, logger=logger, sns_client=_BoomSns(),
            topic_arn="arn:aws:sns:us-west-2:111122223333:t",
        )
        self.assertFalse(result["published"])
        self.assertTrue(any("SNS publish failed" in r for r in logger.warning_records))


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    unittest.main()
