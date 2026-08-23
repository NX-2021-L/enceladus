#!/usr/bin/env python3
"""ENC-TSK-P12 / ENC-ISS-667: tests for the per-component liveness contract.

AC-3's own requirement is the reason this file exists in this shape: "An
alarm that has never been seen red is not evidence it works... build the
proof as an automated test with a synthetic/injected metric state, and be
explicit about what was observed versus simulated." Every test in
TestSyntheticActivityDetection below injects a FAKE CloudWatch response --
no AWS credentials, no network, fully offline -- and asserts the exact
detector code path used by `verify_liveness_contract.py --live`
(fetch_invocation_sum -> evaluate_activity, via check_component_liveness)
reaches ALARM (fail) or OK (pass). These are SIMULATED proofs: they show the
detector's state machine is correct, not that it has been seen firing
against a real production incident.

The session that authored this file ALSO ran the identical detector
functions against real, read-only CloudWatch data for
devops-recompute-governance-gamma at a timestamp inside the account's real
historical gap (2026-08-15, per AWS/Lambda Invocations daily sums showing
zero activity 2026-08-08 through 2026-08-21) and observed a real ALARM
verdict -- that run is OBSERVED, not simulated, and is not repeated here
because it depends on live AWS state this offline suite must not require.
See the ENC-TSK-P12 worklog for that run's real output.
"""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

import verify_liveness_contract as vlc  # noqa: E402


# ---------------------------------------------------------------------------
# Contract structural validation
# ---------------------------------------------------------------------------

def _valid_contract() -> dict:
    """A minimal, fully valid synthetic contract -- independent of the real
    committed file, so these tests exercise the SHAPE contract, not today's
    specific schedule inventory."""
    return {
        "scope_prefixes": {"prefixes": ["enceladus-", "devops-", "rhythm-"]},
        "tolerance_policy": {"multiplier": 3.0, "minimum_hours": 1.0},
        "overrides": {
            "entries": {
                "devops-recompute-governance-gamma": {
                    "expected_activity_within_hours": 26.0,
                    "rationale": "BRD 8.4",
                },
            },
        },
        "devops_ownership_snapshot_path": "infrastructure/devops_lambda_ownership_snapshot.json",
        "legacy_schedule_inventory_module": "backend.lambda.rhythm_cycle.legacy_schedules",
        "rhythm_beat_family": {
            "gating_parameter": "RhythmBeatsEnabled",
            "gating_condition": "RhythmBeatsActive",
            "source": "infrastructure/cloudformation/02-compute.yaml",
            "schedule_name_basenames": [
                "rhythm-sense-hourly", "rhythm-light-integrate", "rhythm-decide-act",
                "rhythm-heavy-integrate", "rhythm-coherence-point",
            ],
        },
        "rhythm_tier_to_schedule_basename": {
            "sense": "rhythm-sense-hourly",
            "light_integrate": "rhythm-light-integrate",
            "decide_act": "rhythm-decide-act",
            "heavy_integrate": "rhythm-heavy-integrate",
            "coherence_point": "rhythm-coherence-point",
        },
        "rhythm_absorbed_legacy_family": {
            "cfn_condition_name": "RhythmAbsorbed",
            "cfn_state_if_pattern": ["RhythmAbsorbed", "DISABLED", "ENABLED"],
            "gating_parameter": "RhythmAbsorbLegacy",
        },
        "io_hold_family": {
            "cfn_condition_name": "UnlearningEnabledCond",
            "cfn_state_if_pattern": ["UnlearningEnabledCond", "ENABLED", "DISABLED"],
            "gating_parameter": "UnlearningEnabled",
            "citation": "ENC-FTR-106",
        },
        "permanently_decommissioned_rules": {
            "entries": [
                {"name_contains": "standing-projection-refresh", "citation": "ENC-ISS-465"},
            ],
        },
    }


class TestContractStructure(unittest.TestCase):
    def test_valid_contract_has_no_errors(self):
        errors = vlc.validate_contract_structure(_valid_contract())
        self.assertEqual(errors, [])

    def test_missing_top_level_key_fails(self):
        contract = _valid_contract()
        del contract["tolerance_policy"]
        errors = vlc.validate_contract_structure(contract)
        self.assertTrue(any("tolerance_policy" in e for e in errors))

    def test_override_missing_rationale_fails(self):
        contract = _valid_contract()
        contract["overrides"]["entries"]["devops-recompute-governance-gamma"].pop("rationale")
        errors = vlc.validate_contract_structure(contract)
        self.assertTrue(any("rationale" in e for e in errors))

    def test_stale_rhythm_absorbed_pattern_fails(self):
        """The exact 'a stale declared exception is itself a violation'
        discipline: if the pattern this contract keys the RhythmAbsorbed
        family off of ever drifts from what 02-compute.yaml actually uses,
        that must fail loudly, not silently stop matching anything."""
        contract = _valid_contract()
        contract["rhythm_absorbed_legacy_family"]["cfn_state_if_pattern"] = ["Something", "Else"]
        errors = vlc.validate_contract_structure(contract)
        self.assertTrue(any("RhythmAbsorbed" in e for e in errors))

    def test_missing_permanently_decommissioned_entries_fails(self):
        contract = _valid_contract()
        contract["permanently_decommissioned_rules"]["entries"] = []
        errors = vlc.validate_contract_structure(contract)
        self.assertTrue(any("permanently_decommissioned_rules" in e for e in errors))

    def test_real_committed_contract_is_valid(self):
        """Positive control: the actual committed liveness_contract.json,
        not a synthetic stand-in."""
        contract = vlc.load_contract()
        errors = vlc.validate_contract_structure(contract)
        self.assertEqual(errors, [], f"real committed contract has structural errors: {errors}")


# ---------------------------------------------------------------------------
# Reused sources actually load (positive controls against the real files --
# mirrors test_verify_devops_ownership_snapshot.py's own "clean result on
# the real snapshot proves the file is well-formed" discipline).
# ---------------------------------------------------------------------------

class TestReusedSourcesLoad(unittest.TestCase):
    def test_devops_ownership_snapshot_reused_successfully(self):
        names, err = vlc.load_devops_owned_function_names()
        self.assertIsNotNone(names, err)
        self.assertEqual(err, "")
        self.assertIn("devops-platform-health", names)
        self.assertIn("devops-glue-crawler-launcher", names)

    def test_legacy_schedule_inventory_reused_successfully(self):
        mapping, err = vlc.load_legacy_rule_to_tier_map()
        self.assertIsNotNone(mapping, err)
        self.assertIn("devops-recompute-governance-backstop-gamma", mapping)
        self.assertEqual(mapping["devops-recompute-governance-backstop-gamma"], "heavy_integrate")

    def test_missing_ownership_snapshot_is_reported_not_silenced(self):
        names, err = vlc.load_devops_owned_function_names(Path("/nonexistent/does-not-exist.json"))
        self.assertIsNone(names)
        self.assertTrue(err)

    def test_missing_legacy_inventory_is_reported_not_silenced(self):
        mapping, err = vlc.load_legacy_rule_to_tier_map(Path("/nonexistent/does-not-exist.py"))
        self.assertIsNone(mapping)
        self.assertTrue(err)


# ---------------------------------------------------------------------------
# Structural CFN parsing against the REAL committed templates.
# ---------------------------------------------------------------------------

@unittest.skipUnless(vlc._HAVE_YAML, "PyYAML not available")
class TestDeclaredCatalogRealTemplates(unittest.TestCase):
    def test_catalog_parses_both_templates(self):
        catalog, errors = vlc.build_declared_catalog()
        self.assertEqual(errors, [], errors)
        self.assertIsNotNone(catalog)
        self.assertGreaterEqual(len(catalog), 40)

    def test_recompute_governance_backstop_declared_both_planes(self):
        catalog, _errors = vlc.build_declared_catalog()
        self.assertIn("prod:events_rule:devops-recompute-governance-backstop", catalog)
        self.assertIn("gamma:events_rule:devops-recompute-governance-backstop-gamma", catalog)

    def test_monitoring_template_schedules_are_included(self):
        """ENC-TSK-P12 live finding: a first pass parsing only 02-compute.yaml
        produced five false UNDECLARED_LIVE_SCHEDULE positives because those
        rules live in 05-monitoring.yaml. Locks in the fix."""
        catalog, _errors = vlc.build_declared_catalog()
        self.assertIn("prod:events_rule:devops-env-drift-auditor-hourly", catalog)
        self.assertIn("gamma:events_rule:enceladus-graph-health-schedule-gamma", catalog)

    def test_conditions_present(self):
        self.assertEqual(vlc.verify_conditions_present(), [])

    def test_permanently_decommissioned_citation_verified(self):
        contract = vlc.load_contract()
        self.assertEqual(vlc.verify_permanently_decommissioned_citations(contract), [])

    def test_stale_citation_is_flagged(self):
        contract = vlc.load_contract()
        import copy
        bad = copy.deepcopy(contract)
        bad["permanently_decommissioned_rules"]["entries"] = [
            {"name_contains": "this-rule-does-not-exist-anywhere", "citation": "NOPE-000"}
        ]
        errors = vlc.verify_permanently_decommissioned_citations(bad)
        self.assertTrue(errors)


# ---------------------------------------------------------------------------
# Cadence -> tolerance parsing. Every case here is a REAL live schedule
# expression observed in the account 2026-08-23 (see the ENC-TSK-P12
# worklog), not an invented example.
# ---------------------------------------------------------------------------

class TestNominalIntervalParsing(unittest.TestCase):
    def test_rate_hour(self):
        self.assertAlmostEqual(vlc.nominal_interval_hours("rate(1 hour)"), 1.0)

    def test_rate_minutes(self):
        self.assertAlmostEqual(vlc.nominal_interval_hours("rate(5 minutes)"), 5 / 60)

    def test_rate_day(self):
        self.assertAlmostEqual(vlc.nominal_interval_hours("rate(1 day)"), 24.0)

    def test_cron_daily_single_hour(self):
        self.assertAlmostEqual(vlc.nominal_interval_hours("cron(0 6 * * ? *)"), 24.0)

    def test_cron_weekly(self):
        self.assertAlmostEqual(vlc.nominal_interval_hours("cron(0 4 ? * SUN *)"), 168.0)

    def test_cron_hourly_star(self):
        self.assertAlmostEqual(vlc.nominal_interval_hours("cron(7 * * * ? *)"), 1.0)

    def test_cron_four_times_daily(self):
        self.assertAlmostEqual(vlc.nominal_interval_hours("cron(15 0,6,12,18 * * ? *)"), 6.0)

    def test_cron_eight_times_daily(self):
        self.assertAlmostEqual(
            vlc.nominal_interval_hours("cron(30 0,3,6,9,12,15,18,21 * * ? *)"), 3.0
        )

    def test_cron_twice_daily(self):
        self.assertAlmostEqual(vlc.nominal_interval_hours("cron(45 0,12 * * ? *)"), 12.0)

    def test_unparseable_returns_none(self):
        self.assertIsNone(vlc.nominal_interval_hours("not a schedule expression"))

    def test_none_expression_returns_none(self):
        self.assertIsNone(vlc.nominal_interval_hours(None))

    def test_tolerance_uses_override_when_present(self):
        contract = _valid_contract()
        hours, note = vlc.expected_tolerance_hours(
            "devops-recompute-governance-gamma", "rate(1 hour)", contract,
        )
        self.assertEqual(hours, 26.0)
        self.assertIn("override", note)

    def test_tolerance_computed_when_no_override(self):
        contract = _valid_contract()
        hours, note = vlc.expected_tolerance_hours("some-other-function", "rate(1 hour)", contract)
        self.assertEqual(hours, 3.0)  # 1h * 3.0 multiplier
        self.assertIn("computed", note)

    def test_tolerance_floored_at_minimum(self):
        contract = _valid_contract()
        hours, _note = vlc.expected_tolerance_hours("some-other-function", "rate(5 minutes)", contract)
        self.assertEqual(hours, 1.0)  # floored, not (5/60)*3


# ---------------------------------------------------------------------------
# ENC-TSK-P12 AC-3: the pure detector, and the same detector wired to a
# SYNTHETIC/INJECTED CloudWatch client. Every AWS interaction in this class
# is fake -- no network, no credentials -- and is explicitly SIMULATED, not
# OBSERVED (see module docstring).
# ---------------------------------------------------------------------------

class TestEvaluateActivityPure(unittest.TestCase):
    def test_none_sum_is_alarm(self):
        state, reason, detail = vlc.evaluate_activity(
            None, component_name="x", expected_within_hours=26.0,
        )
        self.assertEqual(state, vlc.FAIL)
        self.assertEqual(reason, "no_datapoints")
        self.assertIn("ALARM", detail)

    def test_zero_sum_is_alarm(self):
        state, reason, detail = vlc.evaluate_activity(
            0.0, component_name="x", expected_within_hours=26.0,
        )
        self.assertEqual(state, vlc.FAIL)
        self.assertEqual(reason, "zero_invocations")
        self.assertIn("ALARM", detail)

    def test_positive_sum_is_ok(self):
        state, reason, detail = vlc.evaluate_activity(
            3.0, component_name="x", expected_within_hours=26.0,
        )
        self.assertEqual(state, vlc.PASS)
        self.assertEqual(reason, "activity_observed")
        self.assertIn("OK", detail)


class _FakeCloudWatchClient:
    """Injectable stand-in for boto3's CloudWatch client. Returns a
    hand-built GetMetricData-shaped response -- the SAME shape
    fetch_invocation_sum parses in production, so these tests exercise the
    real parsing path, not a shortcut around it."""

    def __init__(self, values):
        self._values = values  # list[float], or None to simulate "no series at all"

    def get_metric_data(self, **kwargs):
        # Assert the query shape is what production actually sends, so this
        # fake cannot silently drift from the real contract.
        query = kwargs["MetricDataQueries"][0]
        assert query["MetricStat"]["Metric"]["Namespace"] == "AWS/Lambda"
        assert query["MetricStat"]["Metric"]["MetricName"] == "Invocations"
        assert query["MetricStat"]["Stat"] == "Sum"
        if self._values is None:
            return {"MetricDataResults": []}
        return {"MetricDataResults": [{"Values": self._values}]}


class _RaisingCloudWatchClient:
    def get_metric_data(self, **kwargs):
        raise RuntimeError("synthetic AWS-side failure (e.g. throttling)")


class TestSyntheticActivityDetection(unittest.TestCase):
    """AC-3: 'build the proof as an automated test with a synthetic/injected
    metric state'. Every case here injects a metric state that never
    touched AWS and asserts the detector reaches the right ALARM/OK verdict.
    """

    def test_synthetic_dead_schedule_no_series_at_all_fires_alarm(self):
        """Simulates a function that has NEVER produced this metric, or
        whose metric fell out of retention -- CloudWatch's GetMetricData
        returns an empty MetricDataResults list."""
        fake = _FakeCloudWatchClient(values=None)
        state, reason, detail = vlc.check_component_liveness(
            fake, "devops-recompute-governance-gamma", 26.0,
            now=datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(state, vlc.FAIL)
        self.assertIn("ALARM", detail)

    def test_synthetic_stopped_schedule_empty_window_fires_alarm(self):
        """Simulates the EXACT ENC-ISS-667 shape: the metric series exists
        (the function used to run) but the tolerance window itself contains
        no datapoints -- an injected empty Values list, standing in for the
        real 365.7h gap this task's defect narrative describes."""
        fake = _FakeCloudWatchClient(values=[])
        state, reason, detail = vlc.check_component_liveness(
            fake, "devops-recompute-governance-gamma", 26.0,
            now=datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(state, vlc.FAIL)
        self.assertEqual(reason, "no_datapoints")

    def test_synthetic_zero_invocations_fires_alarm(self):
        """A returned datapoint whose value is literally 0 must also alarm
        -- some AWS metrics DO backfill zeros; this must not be treated
        differently from 'no datapoints at all'."""
        fake = _FakeCloudWatchClient(values=[0.0])
        state, reason, detail = vlc.check_component_liveness(
            fake, "devops-recompute-governance-gamma", 26.0,
        )
        self.assertEqual(state, vlc.FAIL)
        self.assertEqual(reason, "zero_invocations")

    def test_synthetic_healthy_schedule_clears_alarm(self):
        """Injected healthy state: activity present in-window -> OK, not
        ALARM. Proves the detector is not just alarm-happy -- it actually
        distinguishes the two states."""
        fake = _FakeCloudWatchClient(values=[24.0])
        state, reason, detail = vlc.check_component_liveness(
            fake, "devops-recompute-governance-gamma", 26.0,
        )
        self.assertEqual(state, vlc.PASS)
        self.assertIn("OK", detail)

    def test_synthetic_state_transition_healthy_to_silent_fires_alarm(self):
        """The closest offline analogue to 'observed an alarm fire': the
        same component, same tolerance, same detector code path, evaluated
        against two injected metric states representing before/during a
        gap. The verdict must flip from OK to ALARM -- proving the detector
        actually responds to the injected state rather than returning a
        constant."""
        healthy = _FakeCloudWatchClient(values=[24.0])
        during_gap = _FakeCloudWatchClient(values=[])
        healthy_state, _r1, _d1 = vlc.check_component_liveness(
            healthy, "devops-recompute-governance-gamma", 26.0,
        )
        gap_state, _r2, _d2 = vlc.check_component_liveness(
            during_gap, "devops-recompute-governance-gamma", 26.0,
        )
        self.assertEqual(healthy_state, vlc.PASS)
        self.assertEqual(gap_state, vlc.FAIL)
        self.assertNotEqual(healthy_state, gap_state)

    def test_cloudwatch_error_is_unknown_never_pass_or_fail_misclassified(self):
        """An AWS-side error (throttling, permission denial, ...) must
        surface as UNKNOWN -- collapsing it into FAIL would be a false
        positive risk (crying wolf, ENC-ISS-624 class); collapsing it into
        PASS would be exactly the vacuous-pass failure mode this whole
        contract exists to prevent."""
        state, reason, detail = vlc.check_component_liveness(
            _RaisingCloudWatchClient(), "devops-recompute-governance-gamma", 26.0,
        )
        self.assertEqual(state, vlc.UNKNOWN)
        self.assertEqual(reason, "cloudwatch_error")

    def test_no_cloudwatch_client_in_classify_and_check_is_unknown(self):
        """classify_and_check with cw_client=None (structural-only path)
        must report UNKNOWN for a LIVE-classified component, never silently
        skip it and never fabricate a PASS."""
        contract = _valid_contract()
        item = vlc.LiveItem(
            name="devops-example-hourly", kind="events_rule", plane="prod",
            state="ENABLED", schedule_expression="rate(1 hour)",
            target_function="devops-example",
        )
        declared = {
            "prod:events_rule:devops-example-hourly": vlc.DeclaredResource(
                resource_name="ExampleSchedule", kind="events_rule", plane="prod",
                rendered_name="devops-example-hourly", state_prop="ENABLED",
                schedule_expression_prop="rate(1 hour)", condition=None,
            ),
        }
        findings = vlc.classify_and_check(
            [item], declared, contract, devops_owned=set(), legacy_tier_map={},
            cw_client=None,
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].verdict, vlc.UNKNOWN)


# ---------------------------------------------------------------------------
# End-to-end classification, entirely synthetic live/declared inventories --
# proves every family's logic (ENC-TSK-P12 AC-4) without touching AWS.
# ---------------------------------------------------------------------------

def _declared(kind, plane, rendered_name, state_prop, schedule_expression="rate(1 hour)", condition=None,
              resource_name="Res"):
    return vlc.DeclaredResource(
        resource_name=resource_name, kind=kind, plane=plane, rendered_name=rendered_name,
        state_prop=state_prop, schedule_expression_prop=schedule_expression, condition=condition,
    )


class TestClassifyAndCheckFamilies(unittest.TestCase):
    def setUp(self):
        self.contract = _valid_contract()

    def test_devops_ownership_trumps_all(self):
        item = vlc.LiveItem(
            name="devops-something-daily", kind="events_rule", plane="prod", state="DISABLED",
            schedule_expression="cron(0 6 * * ? *)", target_function="devops-owned-fn",
        )
        findings = vlc.classify_and_check(
            [item], {}, self.contract, devops_owned={"devops-owned-fn"}, legacy_tier_map={},
        )
        self.assertEqual(findings[0].classification, "NOT_APPLICABLE_ON_PLANE")
        self.assertEqual(findings[0].verdict, vlc.PASS)

    def test_rhythm_beats_consistent_state_passes(self):
        items = [
            vlc.LiveItem(name=f"{base}-gamma", kind="scheduler_schedule", plane="gamma",
                         state="DISABLED", schedule_expression="cron(0 * * * ? *)",
                         target_function="enceladus-rhythm-cycle-gamma")
            for base in self.contract["rhythm_beat_family"]["schedule_name_basenames"]
        ]
        findings = vlc.classify_and_check(items, {}, self.contract, devops_owned=set(), legacy_tier_map={})
        self.assertEqual(len(findings), 5)
        self.assertTrue(all(f.verdict == vlc.PASS for f in findings))
        self.assertTrue(all(f.classification == "DELIBERATELY_PAUSED_RHYTHM_BEAT" for f in findings))

    def test_rhythm_beats_mixed_state_fails_all(self):
        basenames = self.contract["rhythm_beat_family"]["schedule_name_basenames"]
        items = [
            vlc.LiveItem(name=f"{base}-gamma", kind="scheduler_schedule", plane="gamma",
                         state=("ENABLED" if i == 0 else "DISABLED"),
                         schedule_expression="cron(0 * * * ? *)",
                         target_function="enceladus-rhythm-cycle-gamma")
            for i, base in enumerate(basenames)
        ]
        findings = vlc.classify_and_check(items, {}, self.contract, devops_owned=set(), legacy_tier_map={})
        self.assertEqual(len(findings), 5)
        self.assertTrue(all(f.verdict == vlc.FAIL for f in findings))
        self.assertTrue(all(f.classification == "RHYTHM_BEAT_MIXED_STATE" for f in findings))

    def test_rhythm_absorbed_contradiction_when_tier_disabled(self):
        item = vlc.LiveItem(
            name="devops-recompute-governance-backstop-gamma", kind="events_rule", plane="gamma",
            state="DISABLED", schedule_expression="rate(1 hour)",
            target_function="devops-recompute-governance-gamma",
        )
        tier_item = vlc.LiveItem(
            name="rhythm-heavy-integrate-gamma", kind="scheduler_schedule", plane="gamma",
            state="DISABLED", schedule_expression="cron(45 0,12 * * ? *)",
            target_function="enceladus-rhythm-cycle-gamma",
        )
        declared = {
            "gamma:events_rule:devops-recompute-governance-backstop-gamma": _declared(
                "events_rule", "gamma", "devops-recompute-governance-backstop-gamma",
                {"!If": ["RhythmAbsorbed", "DISABLED", "ENABLED"]},
            ),
        }
        legacy_map = {"devops-recompute-governance-backstop-gamma": "heavy_integrate"}
        findings = vlc.classify_and_check(
            [item, tier_item], declared, self.contract, devops_owned=set(), legacy_tier_map=legacy_map,
        )
        backstop_finding = next(f for f in findings if f.name == "devops-recompute-governance-backstop-gamma")
        self.assertEqual(backstop_finding.classification, "LEGACY_SUPERSEDED_CONTRADICTION")
        self.assertEqual(backstop_finding.verdict, vlc.FAIL)
        self.assertIn("ENC-ISS-667", backstop_finding.detail)

    def test_rhythm_absorbed_ok_when_tier_enabled(self):
        item = vlc.LiveItem(
            name="devops-recompute-governance-backstop-gamma", kind="events_rule", plane="gamma",
            state="DISABLED", schedule_expression="rate(1 hour)",
            target_function="devops-recompute-governance-gamma",
        )
        tier_item = vlc.LiveItem(
            name="rhythm-heavy-integrate-gamma", kind="scheduler_schedule", plane="gamma",
            state="ENABLED", schedule_expression="cron(45 0,12 * * ? *)",
            target_function="enceladus-rhythm-cycle-gamma",
        )
        declared = {
            "gamma:events_rule:devops-recompute-governance-backstop-gamma": _declared(
                "events_rule", "gamma", "devops-recompute-governance-backstop-gamma",
                {"!If": ["RhythmAbsorbed", "DISABLED", "ENABLED"]},
            ),
        }
        legacy_map = {"devops-recompute-governance-backstop-gamma": "heavy_integrate"}
        findings = vlc.classify_and_check(
            [item, tier_item], declared, self.contract, devops_owned=set(), legacy_tier_map=legacy_map,
        )
        backstop_finding = next(f for f in findings if f.name == "devops-recompute-governance-backstop-gamma")
        self.assertEqual(backstop_finding.classification, "LEGACY_SUPERSEDED")
        self.assertEqual(backstop_finding.verdict, vlc.PASS)

    def test_io_hold_disabled_is_deliberate(self):
        item = vlc.LiveItem(
            name="devops-unlearning-nightly-gamma", kind="events_rule", plane="gamma",
            state="DISABLED", schedule_expression="cron(0 4 * * ? *)",
            target_function="enceladus-unlearning-gamma",
        )
        declared = {
            "gamma:events_rule:devops-unlearning-nightly-gamma": _declared(
                "events_rule", "gamma", "devops-unlearning-nightly-gamma",
                {"!If": ["UnlearningEnabledCond", "ENABLED", "DISABLED"]},
            ),
        }
        findings = vlc.classify_and_check([item], declared, self.contract, devops_owned=set(), legacy_tier_map={})
        self.assertEqual(findings[0].classification, "DELIBERATELY_PAUSED_IO_HOLD")
        self.assertEqual(findings[0].verdict, vlc.PASS)

    def test_permanently_decommissioned_reenabled_is_contradiction(self):
        item = vlc.LiveItem(
            name="enceladus-standing-projection-refresh", kind="events_rule", plane="prod",
            state="ENABLED", schedule_expression="rate(30 minutes)",
            target_function="devops-graph-query-api",
        )
        declared = {
            "prod:events_rule:enceladus-standing-projection-refresh": _declared(
                "events_rule", "prod", "enceladus-standing-projection-refresh", "DISABLED",
            ),
        }
        findings = vlc.classify_and_check([item], declared, self.contract, devops_owned=set(), legacy_tier_map={})
        self.assertEqual(findings[0].classification, "PERMANENTLY_DECOMMISSIONED_CONTRADICTION")
        self.assertEqual(findings[0].verdict, vlc.FAIL)

    def test_orphaned_cross_service_stale_resource(self):
        item = vlc.LiveItem(
            name="devops-governance-mart-daily-gamma", kind="events_rule", plane="gamma",
            state="DISABLED", schedule_expression="cron(0 6 * * ? *)",
            target_function="devops-governance-mart-gamma",
        )
        declared = {
            "gamma:scheduler_schedule:devops-governance-mart-daily-gamma": _declared(
                "scheduler_schedule", "gamma", "devops-governance-mart-daily-gamma", "DISABLED",
                resource_name="GovernanceMartScheduleGamma",
            ),
        }
        findings = vlc.classify_and_check([item], declared, self.contract, devops_owned=set(), legacy_tier_map={})
        self.assertEqual(findings[0].classification, "ORPHANED_CROSS_SERVICE_STALE_RESOURCE")
        self.assertEqual(findings[0].verdict, vlc.FAIL)

    def test_undeclared_live_schedule(self):
        item = vlc.LiveItem(
            name="devops-brand-new-nobody-declared-gamma", kind="events_rule", plane="gamma",
            state="ENABLED", schedule_expression="rate(1 hour)", target_function="devops-mystery",
        )
        findings = vlc.classify_and_check(
            [item], {}, self.contract, devops_owned=set(), legacy_tier_map={},
        )
        self.assertEqual(findings[0].classification, "UNDECLARED_LIVE_SCHEDULE")
        self.assertEqual(findings[0].verdict, vlc.FAIL)

    def test_unresolved_disabled(self):
        item = vlc.LiveItem(
            name="devops-mystery-disabled-gamma", kind="events_rule", plane="gamma",
            state="DISABLED", schedule_expression="cron(0 6 * * ? *)", target_function="devops-mystery",
        )
        declared = {
            "gamma:events_rule:devops-mystery-disabled-gamma": _declared(
                "events_rule", "gamma", "devops-mystery-disabled-gamma", "DISABLED",
            ),
        }
        findings = vlc.classify_and_check([item], declared, self.contract, devops_owned=set(), legacy_tier_map={})
        self.assertEqual(findings[0].classification, "UNRESOLVED_DISABLED")
        self.assertEqual(findings[0].verdict, vlc.FAIL)

    def test_out_of_scope_event_pattern_rule(self):
        item = vlc.LiveItem(
            name="devops-deploy-codebuild-finalize", kind="events_rule", plane="prod",
            state="ENABLED", schedule_expression=None, target_function=None,
        )
        findings = vlc.classify_and_check([item], {}, self.contract, devops_owned=set(), legacy_tier_map={})
        self.assertEqual(findings[0].classification, "OUT_OF_SCOPE_NOT_SCHEDULED")
        self.assertEqual(findings[0].verdict, vlc.PASS)

    def test_live_enabled_declared_no_cloudwatch_client_is_unknown_never_pass(self):
        item = vlc.LiveItem(
            name="enceladus-something-hourly", kind="events_rule", plane="prod",
            state="ENABLED", schedule_expression="rate(1 hour)", target_function="enceladus-something",
        )
        declared = {
            "prod:events_rule:enceladus-something-hourly": _declared(
                "events_rule", "prod", "enceladus-something-hourly", "ENABLED",
            ),
        }
        findings = vlc.classify_and_check([item], declared, self.contract, devops_owned=set(), legacy_tier_map={})
        self.assertEqual(findings[0].classification, "LIVE")
        self.assertEqual(findings[0].verdict, vlc.UNKNOWN)

    def test_override_component_direct_check_runs_unconditionally(self):
        """ENC-TSK-P12 AC-1/AC-2: devops-recompute-governance-gamma (named
        in overrides.entries) gets a direct CloudWatch check even when the
        live_items list contains nothing for it at all -- the check must
        not depend on correctly tracing which EventBridge resource claims
        to trigger it."""
        fake_cw = _FakeCloudWatchClient(values=[1.0])
        findings = vlc.classify_and_check(
            [], {}, self.contract, devops_owned=set(), legacy_tier_map={}, cw_client=fake_cw,
        )
        direct_checks = [f for f in findings if f.classification == "LIVE_COMPONENT_DIRECT_CHECK"]
        self.assertEqual(len(direct_checks), 1)
        self.assertEqual(direct_checks[0].name, "devops-recompute-governance-gamma")
        self.assertEqual(direct_checks[0].verdict, vlc.PASS)

    def test_override_component_direct_check_fires_alarm_on_synthetic_gap(self):
        """Same as above, but with the synthetic gap injected -- this is
        the single most direct proof of AC-1+AC-2+AC-3 together: the exact
        function named in the ENC-TSK-P12 brief, checked by the exact code
        path `--live` uses, against an injected empty metric series."""
        fake_cw = _FakeCloudWatchClient(values=[])
        findings = vlc.classify_and_check(
            [], {}, self.contract, devops_owned=set(), legacy_tier_map={}, cw_client=fake_cw,
        )
        direct_checks = [f for f in findings if f.classification == "LIVE_COMPONENT_DIRECT_CHECK"]
        self.assertEqual(len(direct_checks), 1)
        self.assertEqual(direct_checks[0].name, "devops-recompute-governance-gamma")
        self.assertEqual(direct_checks[0].verdict, vlc.FAIL)
        self.assertIn("ALARM", direct_checks[0].detail)


class TestReconcileDeclaredNotLive(unittest.TestCase):
    def test_declared_not_live_is_informational_only(self):
        declared = {
            "prod:events_rule:devops-something": _declared(
                "events_rule", "prod", "devops-something", "ENABLED",
            ),
        }
        notes = vlc.reconcile_declared_not_live(declared, [])
        self.assertEqual(len(notes), 1)
        self.assertIn("devops-something", notes[0])


if __name__ == "__main__":
    unittest.main()
