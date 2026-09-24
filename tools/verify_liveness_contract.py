#!/usr/bin/env python3
"""ENC-TSK-P12 / ENC-ISS-667: per-component liveness contract.

THE DEFECT THIS CLOSES
-----------------------------------------------------------------------------
devops-recompute-governance-gamma's schedule silently stopped for ~15 days
(365.7h against a 26h expectation). Nothing errored, nothing alarmed. It
was caught only because a newly-registered point-4 liveness probe in
tools/verify_arm64_validation_harness.py happened to look -- and 49 of 51
functions had no such probe, so the same silence anywhere else was (and,
before this file, still is) invisible. ENC-TSK-O81's dead-man's-switch was
built mart-specific; silent-cron-death is a universal property of every
scheduled component, not a mart quirk.

WHY THIS IS NOT verify_arm64_validation_harness.py's POINT 4, AGAIN
-----------------------------------------------------------------------------
That harness's point-4 probe (a) only runs when someone manually invokes the
five-point harness FOR THAT ONE FUNCTION, so its coverage is exactly as wide
as whoever remembered to register a probe (2 function families today), and
(b) reads CloudWatch Logs mid-flight relative to the harness's OWN run. This
file is deliberately independent of it (ENC-TSK-P12 AC-2): it is never
imported by, does not import, and does not invoke
tools/verify_arm64_validation_harness.py or any component it checks. It
reads only AWS/Lambda's own Invocations metric -- a value CloudWatch
publishes automatically as a side effect of a REAL invocation this tool did
not cause -- over a declared tolerance window. Two independently-motivated
detectors agreeing is stronger evidence than one detector asked twice.

THE CONTRACT: TWO HALVES
-----------------------------------------------------------------------------
infrastructure/liveness_contract.json is the DECLARATIVE half: tolerances,
named deliberate-pause families, and overrides -- things AWS cannot tell you
because they are business decisions, not observable facts. This file is the
DETECTOR: it derives WHAT is scheduled from the account itself (EventBridge
Rules AND EventBridge Scheduler -- two different APIs; ENC-TSK-P13/P15's
enceladus-checkout-service-auto-gamma blindness is this same shape of gap
one layer up -- a coverage predicate that reads only ONE source), reconciles
it against the declared contract PLUS two already-governed sources it reuses
rather than re-declaring (infrastructure/devops_lambda_ownership_snapshot.json,
ENC-TSK-P15; backend/lambda/rhythm_cycle/legacy_schedules.py, K91), and
resolves every live schedule to exactly one of:
  * LIVE      -- checked for real activity against CloudWatch.
  * a named, checkable governed exception (devops ownership, a deliberate
    pause family, a legacy-supersession claim that is cross-checked against
    whether the claimed successor is actually alive, or a permanent
    decommission) -- printed every run, never a silent skip.
  * a FAIL    -- a disabled schedule matching no family, a live schedule
    declared nowhere, or a governed exception whose own precondition does
    not hold (see "THE CONTRADICTION CHECK" below).
Nothing escapes by not being named (ENC-TSK-P12 AC-4).

THE CONTRADICTION CHECK -- THE MECHANISM, MADE CHECKABLE
-----------------------------------------------------------------------------
02-compute.yaml gates several legacy EventBridge Rules on the RhythmAbsorbed
condition: State: !If [RhythmAbsorbed, DISABLED, ENABLED]. A disabled rule
under this condition is a live claim -- "the rhythm cycle now does this
instead" -- and that claim is only true if the rhythm pacemaker is actually
running. Verified live 2026-08-23: it is not (all five rhythm beat schedules
report State=DISABLED, ENC-TSK-N78's documented cost-stop). This tool cross-
checks that claim structurally-detected + live-verified, rather than trusting
the CFN comment: a RhythmAbsorbed-gated rule that is disabled while its
named (or, absent a specific mapping, ANY) rhythm tier is also disabled is a
CONTRADICTION, reported as FAIL, citing ENC-ISS-667 -- this is the exact
mechanism by which the incident happened, made into a standing assertion so
it cannot happen again by the same route without this tool saying so.

TWO-TIER EXECUTION (mirrors tools/verify_devops_ownership_snapshot.py)
-----------------------------------------------------------------------------
Default (no flags): STRUCTURAL checks only -- contract schema, the two
reused sources load and are non-empty, 02-compute.yaml parses and the
RhythmAbsorbed/UnlearningEnabledCond conditions and the declared permanent-
decommission citations are still present as expected. No AWS calls; this is
what CI runs on every PR, credential-free, same as every other guard in this
file's family.

--live: the full account-derived reconciliation (EventBridge Rules +
EventBridge Scheduler enumeration, target resolution, family cross-checks,
CloudWatch Invocations activity checks). Needs boto3 and AWS credentials.
Not wired into ci.yml (which has none configured, same reasoning
verify_lambda_arch_parity.py's --check-live-reconciliation documents) --
this is what a human or a credentialed ops job runs, and what this session
ran directly for the evidence in its worklog.

Exit 0 = structural check(s) passed (and, with --live, live reconciliation
         found no violation).
Exit 1 = a structural violation, or (with --live) a live violation
         (contradiction, undeclared live schedule, unresolved disablement,
         or observed silence past tolerance).
Exit 2 = the guard could not run at all (missing/malformed contract file).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
CONTRACT_PATH = REPO_ROOT / "infrastructure" / "liveness_contract.json"
OWNERSHIP_SNAPSHOT_PATH = REPO_ROOT / "infrastructure" / "devops_lambda_ownership_snapshot.json"
LEGACY_SCHEDULES_PATH = REPO_ROOT / "backend" / "lambda" / "rhythm_cycle" / "legacy_schedules.py"
CFN_TEMPLATE_PATH = REPO_ROOT / "infrastructure" / "cloudformation" / "02-compute.yaml"
# ENC-TSK-P12 live finding (2026-08-23): a first pass that parsed only
# 02-compute.yaml produced FIVE false UNDECLARED_LIVE_SCHEDULE findings
# (devops-env-drift-auditor-hourly[-gamma], devops-parity-drift-daily,
# enceladus-health-probe-schedule[-gamma], enceladus-mcp-gamma-synthetic-
# schedule-gamma, enceladus-graph-health-schedule-gamma) -- all five are
# declared, just in 05-monitoring.yaml, a SECOND template this account's
# schedules live in. A reconciliation that reads only one CFN file has the
# same shape blind spot as one that reads only one AWS API (the AC-4 warning
# this whole file exists to satisfy) -- so every governed CFN template that
# can declare AWS::Events::Rule / AWS::Scheduler::Schedule resources is
# parsed, not just the largest one.
CFN_MONITORING_TEMPLATE_PATH = REPO_ROOT / "infrastructure" / "cloudformation" / "05-monitoring.yaml"
CFN_TEMPLATE_PATHS = (CFN_TEMPLATE_PATH, CFN_MONITORING_TEMPLATE_PATH)

DEFAULT_REGION = "us-west-2"

PASS = "pass"
FAIL = "fail"
UNKNOWN = "unknown"
_VALID_STATES = (PASS, FAIL, UNKNOWN)


def log(message: str) -> None:
    print(f"[liveness-contract] {message}")


# ---------------------------------------------------------------------------
# Contract loading + structural self-consistency
# ---------------------------------------------------------------------------

REQUIRED_CONTRACT_KEYS = (
    "scope_prefixes",
    "tolerance_policy",
    "overrides",
    "devops_ownership_snapshot_path",
    "legacy_schedule_inventory_module",
    "rhythm_beat_family",
    "rhythm_tier_to_schedule_basename",
    "rhythm_absorbed_legacy_family",
    "io_hold_family",
    "permanently_decommissioned_rules",
)


def load_contract(path: Path = CONTRACT_PATH) -> dict:
    if not path.is_file():
        print(f"::error::missing liveness contract: {path}")
        sys.exit(2)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"::error::{path} is not valid JSON: {exc}")
        sys.exit(2)


def validate_contract_structure(contract: dict) -> List[str]:
    errors: List[str] = []
    for key in REQUIRED_CONTRACT_KEYS:
        if key not in contract:
            errors.append(f"liveness contract missing required top-level key: {key!r}")
    if errors:
        return errors

    prefixes = contract["scope_prefixes"].get("prefixes")
    if not isinstance(prefixes, list) or not prefixes or not all(isinstance(p, str) for p in prefixes):
        errors.append("scope_prefixes.prefixes must be a non-empty list of strings")

    tol = contract["tolerance_policy"]
    if not isinstance(tol.get("multiplier"), (int, float)) or tol["multiplier"] <= 0:
        errors.append("tolerance_policy.multiplier must be a positive number")
    if not isinstance(tol.get("minimum_hours"), (int, float)) or tol["minimum_hours"] <= 0:
        errors.append("tolerance_policy.minimum_hours must be a positive number")

    overrides = contract["overrides"].get("entries", {})
    for name, entry in overrides.items():
        hours = entry.get("expected_activity_within_hours")
        if not isinstance(hours, (int, float)) or hours <= 0:
            errors.append(f"overrides.entries[{name!r}].expected_activity_within_hours must be a positive number")
        if not entry.get("rationale"):
            errors.append(f"overrides.entries[{name!r}] missing rationale")

    rbf = contract["rhythm_beat_family"]
    basenames = rbf.get("schedule_name_basenames")
    if not isinstance(basenames, list) or len(basenames) != 5:
        errors.append("rhythm_beat_family.schedule_name_basenames must list exactly the five beat schedules")

    tier_map = contract["rhythm_tier_to_schedule_basename"]
    for k in ("sense", "light_integrate", "decide_act", "heavy_integrate", "coherence_point"):
        if k not in tier_map:
            errors.append(f"rhythm_tier_to_schedule_basename missing tier {k!r}")

    ral = contract["rhythm_absorbed_legacy_family"]
    if ral.get("cfn_state_if_pattern") != ["RhythmAbsorbed", "DISABLED", "ENABLED"]:
        errors.append(
            "rhythm_absorbed_legacy_family.cfn_state_if_pattern no longer matches the expected "
            "!If [RhythmAbsorbed, DISABLED, ENABLED] shape -- this is a stale declared exception, "
            "not a silent pass (same discipline as a stale devops-ownership entry)."
        )

    iohold = contract["io_hold_family"]
    if iohold.get("cfn_state_if_pattern") != ["UnlearningEnabledCond", "ENABLED", "DISABLED"]:
        errors.append(
            "io_hold_family.cfn_state_if_pattern no longer matches the expected "
            "!If [UnlearningEnabledCond, ENABLED, DISABLED] shape -- stale declared exception."
        )

    pdr = contract["permanently_decommissioned_rules"].get("entries", [])
    if not isinstance(pdr, list) or not pdr:
        errors.append("permanently_decommissioned_rules.entries must be a non-empty list")
    for entry in pdr if isinstance(pdr, list) else []:
        if not entry.get("name_contains") or not entry.get("citation"):
            errors.append(f"permanently_decommissioned_rules entry missing name_contains/citation: {entry!r}")

    return errors


# ---------------------------------------------------------------------------
# Reused source #1: devops Lambda ownership snapshot (ENC-TSK-P15).
# Membership check only -- tools/verify_devops_ownership_snapshot.py already
# owns full schema validation of this file and is wired into CI separately;
# re-validating it here would be a second ownership mechanism, which the
# ENC-TSK-P12 brief explicitly says not to build.
# ---------------------------------------------------------------------------

def load_devops_owned_function_names(path: Path = OWNERSHIP_SNAPSHOT_PATH) -> Tuple[Optional[Set[str]], str]:
    if not path.is_file():
        return None, f"devops ownership snapshot not found at {path}"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return None, f"devops ownership snapshot is not valid JSON: {exc}"
    names = {
        entry["function_name"]
        for entry in data.get("functions", [])
        if isinstance(entry, dict) and entry.get("function_name")
    }
    if not names:
        return None, f"devops ownership snapshot at {path} declares zero functions"
    return names, ""


# ---------------------------------------------------------------------------
# Reused source #2: rhythm-tier legacy-supersession map (K91).
# Loaded by file path via importlib (backend/lambda has no package
# __init__.py anywhere and legacy_schedules.py has no relative imports of
# its own, so this is safe and avoids sys.path pollution).
# ---------------------------------------------------------------------------

def load_legacy_rule_to_tier_map(path: Path = LEGACY_SCHEDULES_PATH) -> Tuple[Optional[Dict[str, str]], str]:
    if not path.is_file():
        return None, f"legacy schedule inventory not found at {path}"
    try:
        spec = importlib.util.spec_from_file_location("_enc_tsk_p12_legacy_schedules", path)
        if spec is None or spec.loader is None:
            return None, f"could not build an import spec for {path}"
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001
        return None, f"legacy schedule inventory at {path} failed to import: {exc}"
    inventory = getattr(module, "LEGACY_SCHEDULE_INVENTORY", None)
    if not isinstance(inventory, list) or not inventory:
        return None, f"{path} has no non-empty LEGACY_SCHEDULE_INVENTORY list"
    mapping: Dict[str, str] = {}
    for entry in inventory:
        if isinstance(entry, dict) and entry.get("rule_name") and entry.get("rhythm_tier"):
            mapping[entry["rule_name"]] = entry["rhythm_tier"]
    return mapping, ""


# ---------------------------------------------------------------------------
# Structural CFN parsing -- reuses the tag-preserving YAML loader already
# established by tools/verify_lambda_arch_parity.py (ENC-TSK-O83) and reused
# again by tools/verify_cross_plane_arn_isolation.py (ENC-TSK-P15), rather
# than defining a third one.
# ---------------------------------------------------------------------------

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from verify_lambda_arch_parity import _CfnTagPreservingLoader as _CfnLoader  # noqa: E402
    _HAVE_YAML = True
except ImportError:  # pragma: no cover - exercised only when PyYAML is absent
    _CfnLoader = None  # type: ignore[assignment]
    _HAVE_YAML = False

SCHEDULE_RESOURCE_TYPES = {
    "AWS::Events::Rule": "events_rule",
    "AWS::Scheduler::Schedule": "scheduler_schedule",
}

_PLANE_SUFFIX = {"prod": "", "gamma": "-gamma"}


def _sub_text(value: Any) -> Optional[str]:
    """The raw template text of a literal string or an Fn::Sub, else None."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and "!Sub" in value:
        sub = value["!Sub"]
        if isinstance(sub, str):
            return sub
        if isinstance(sub, list) and sub and isinstance(sub[0], str):
            return sub[0]
    return None


def _render_name(name_prop: Any, suffix: str) -> Optional[str]:
    text = _sub_text(name_prop)
    if text is None:
        return None
    return text.replace("${EnvironmentSuffix}", suffix)


def _applicable_planes(condition: Optional[str]) -> List[str]:
    """Which plane(s) a Resources{} entry renders into, based on its
    resource-level `Condition:` key. Every AWS::Events::Rule /
    AWS::Scheduler::Schedule resource in 02-compute.yaml today uses one of
    exactly these three shapes (verified by inspection, ENC-TSK-P12); an
    unrecognized condition name is treated as "both planes, unverified" --
    safer than silently excluding a resource this tool has never seen
    before, and any resulting false "declared but not live" note is
    reported as INFO, never a failure (see reconcile_declared_not_live)."""
    if condition is None:
        return ["prod", "gamma"]
    if condition == "IsGamma":
        return ["gamma"]
    if condition == "IsProduction":
        return ["prod"]
    return ["prod", "gamma"]


@dataclass
class DeclaredResource:
    resource_name: str
    kind: str
    plane: str
    rendered_name: str
    state_prop: Any
    schedule_expression_prop: Any
    condition: Optional[str]


def _parse_one_template(template_path: Path) -> Tuple[Optional[Dict[str, DeclaredResource]], List[str]]:
    errors: List[str] = []
    if not template_path.is_file():
        return None, [f"CFN template not found: {template_path}"]
    try:
        text = template_path.read_text(encoding="utf-8")
        document = __import__("yaml").load(text, Loader=_CfnLoader) or {}
    except Exception as exc:  # noqa: BLE001
        return None, [f"failed to parse {template_path}: {exc}"]

    resources = document.get("Resources", {})
    if not isinstance(resources, dict) or not resources:
        return None, [f"{template_path} has no Resources{{}} block"]

    catalog: Dict[str, DeclaredResource] = {}
    for res_name, res in resources.items():
        if not isinstance(res, dict):
            continue
        kind = SCHEDULE_RESOURCE_TYPES.get(res.get("Type"))
        if kind is None:
            continue
        props = res.get("Properties") or {}
        condition = res.get("Condition")
        name_prop = props.get("Name")
        for plane in _applicable_planes(condition):
            rendered = _render_name(name_prop, _PLANE_SUFFIX[plane])
            if not rendered:
                continue
            key = f"{plane}:{kind}:{rendered}"
            catalog[key] = DeclaredResource(
                resource_name=f"{template_path.name}:{res_name}",
                kind=kind,
                plane=plane,
                rendered_name=rendered,
                state_prop=props.get("State"),
                schedule_expression_prop=props.get("ScheduleExpression"),
                condition=condition,
            )
    return catalog, errors


def build_declared_catalog(
    template_paths: Tuple[Path, ...] = CFN_TEMPLATE_PATHS,
) -> Tuple[Optional[Dict[str, DeclaredResource]], List[str]]:
    """Structural (no-AWS) catalog of every declared Events::Rule /
    Scheduler::Schedule across every governed CFN template that can declare
    one, keyed by "<plane>:<kind>:<rendered_name>".

    This is the DECLARED side of the AC-4 reconciliation, and it is also
    what the structural (no-AWS) CI mode uses to sanity-check that parsing
    still finds a plausible number of resources -- entirely independent of
    any live AWS call.
    """
    if not _HAVE_YAML:
        return None, ["PyYAML is required to parse the CFN templates (pip install pyyaml)"]

    catalog: Dict[str, DeclaredResource] = {}
    errors: List[str] = []
    any_loaded = False
    for template_path in template_paths:
        sub_catalog, sub_errors = _parse_one_template(template_path)
        errors += sub_errors
        if sub_catalog is None:
            continue
        any_loaded = True
        for key, res in sub_catalog.items():
            if key in catalog and catalog[key].resource_name != res.resource_name:
                errors.append(
                    f"declared-resource key collision: {key!r} is declared by both "
                    f"{catalog[key].resource_name} and {res.resource_name} -- two different "
                    f"CFN resources rendering the identical (plane, kind, name). This must be "
                    f"resolved, not silently merged."
                )
            catalog[key] = res

    if not any_loaded:
        return None, errors

    if len(catalog) < 20:
        errors.append(
            f"only {len(catalog)} declared Events::Rule/Scheduler::Schedule resource(s) found "
            f"across {[str(p.relative_to(REPO_ROOT)) for p in template_paths]} across both planes "
            f"-- expected at least 40 based on ENC-TSK-P12's own census (2026-08-23). This is "
            f"almost certainly a parse regression, not a real shrink; failing loudly rather than "
            f"silently reconciling against an undercounted catalog."
        )
    return catalog, errors


_STATE_IF_RE_CACHE: Dict[Tuple[str, str, str], bool] = {}


def _state_matches_if_pattern(state_prop: Any, pattern: List[str]) -> bool:
    """True iff state_prop is exactly {"!If": [cond, if_true, if_false]}
    matching `pattern` -- the tag-preserving loader's shape for
    `State: !If [Cond, A, B]`."""
    if not isinstance(state_prop, dict) or "!If" not in state_prop:
        return False
    value = state_prop["!If"]
    return isinstance(value, list) and value == pattern


def verify_permanently_decommissioned_citations(
    contract: dict, template_path: Path = CFN_TEMPLATE_PATH,
) -> List[str]:
    """Raw-text proximity check: every permanently_decommissioned_rules
    entry's name_contains and citation strings must both appear within the
    same ~10-line resource block in the CFN source. A stale declared
    exception (comment removed, rule renamed) is itself a violation --
    never a silently-continuing pass (mirrors
    verify_devops_ownership_snapshot.py's digest-mismatch-is-a-refusal
    discipline, applied to a text citation instead of a hash)."""
    errors: List[str] = []
    if not template_path.is_file():
        return [f"CFN template not found: {template_path}"]
    lines = template_path.read_text(encoding="utf-8").splitlines()
    entries = contract.get("permanently_decommissioned_rules", {}).get("entries", [])
    for entry in entries:
        name_contains = entry.get("name_contains", "")
        citation = entry.get("citation", "")
        found = False
        for i, line in enumerate(lines):
            if name_contains in line and "Name:" in line:
                window = "\n".join(lines[i : i + 10])
                if "State: DISABLED" in window and citation in window:
                    found = True
                    break
        if not found:
            errors.append(
                f"permanently_decommissioned_rules entry for {name_contains!r} (citation "
                f"{citation!r}) could not be verified against {template_path} -- expected a "
                f"'State: DISABLED' line and the citation text within the same resource block. "
                f"Either the rule was renamed/re-enabled/the comment was edited, or this "
                f"declared exception has gone stale. A stale declared exception is a violation, "
                f"not a silent pass."
            )
    return errors


def verify_conditions_present(template_path: Path = CFN_TEMPLATE_PATH) -> List[str]:
    """Cheap structural freshness check: the two named conditions this
    contract's family logic keys off of must still exist in 02-compute.yaml,
    or the whole rhythm_absorbed_legacy_family / io_hold_family mechanism is
    checking a pattern that no longer occurs anywhere."""
    errors: List[str] = []
    if not _HAVE_YAML or not template_path.is_file():
        return errors  # covered by build_declared_catalog's own errors already
    try:
        text = template_path.read_text(encoding="utf-8")
        document = __import__("yaml").load(text, Loader=_CfnLoader) or {}
    except Exception as exc:  # noqa: BLE001
        return [f"failed to parse {template_path} for Conditions check: {exc}"]
    conditions = document.get("Conditions", {})
    for name in ("RhythmAbsorbed", "UnlearningEnabledCond"):
        if name not in conditions:
            errors.append(
                f"Conditions.{name} no longer exists in {template_path} -- "
                f"rhythm_absorbed_legacy_family/io_hold_family's structural pattern-match "
                f"can never fire; this is a stale declared mechanism, treat as a violation."
            )
    return errors


# ---------------------------------------------------------------------------
# Cadence -> tolerance
# ---------------------------------------------------------------------------

_RATE_RE = re.compile(r"^rate\((\d+)\s+(minute|minutes|hour|hours|day|days)\)$")
_CRON_RE = re.compile(r"^cron\(([^)]*)\)$")
_UNIT_HOURS = {
    "minute": 1 / 60, "minutes": 1 / 60,
    "hour": 1.0, "hours": 1.0,
    "day": 24.0, "days": 24.0,
}


def nominal_interval_hours(expression: Optional[str]) -> Optional[float]:
    """Best-effort nominal fire interval, in hours, from a raw
    ScheduleExpression string. Returns None when the expression cannot be
    confidently parsed -- callers must treat None as "needs an explicit
    override in liveness_contract.json", never as "assume hourly" or any
    other silent default (ENC-TSK-P12 AC-1/AC-4: nothing gets a made-up
    expectation)."""
    if not expression:
        return None
    expression = expression.strip()
    m = _RATE_RE.match(expression)
    if m:
        n = int(m.group(1))
        return n * _UNIT_HOURS[m.group(2)]
    m2 = _CRON_RE.match(expression)
    if not m2:
        return None
    fields = m2.group(1).split()
    if len(fields) < 5:
        return None
    _minute, hour, _dom, _month, dow = fields[0], fields[1], fields[2], fields[3], fields[4]
    weekly = dow not in ("*", "?")
    if hour == "*":
        base_hours = 1.0
    else:
        count = len([h for h in hour.split(",") if h])
        if count <= 0:
            return None
        base_hours = 24.0 / count
    return base_hours * (7.0 if weekly else 1.0)


def expected_tolerance_hours(
    component_name: str, schedule_expression: Optional[str], contract: dict,
) -> Tuple[Optional[float], str]:
    """Returns (hours, source_note). hours is None when no override exists
    AND the expression could not be parsed -- callers must treat that as
    UNKNOWN, never PASS."""
    overrides = contract["overrides"].get("entries", {})
    if component_name in overrides:
        entry = overrides[component_name]
        return float(entry["expected_activity_within_hours"]), f"override ({entry.get('rationale', '')[:80]}...)"
    nominal = nominal_interval_hours(schedule_expression)
    if nominal is None:
        return None, f"could not derive a nominal interval from {schedule_expression!r}"
    tol = contract["tolerance_policy"]
    hours = max(nominal * float(tol["multiplier"]), float(tol["minimum_hours"]))
    return hours, f"computed: {nominal:g}h nominal x{tol['multiplier']:g} (floor {tol['minimum_hours']:g}h)"


# ---------------------------------------------------------------------------
# The pure detector: CloudWatch Invocations activity, evaluated against a
# tolerance window. Deliberately separated from the AWS call itself
# (fetch_invocation_sum) so it is directly, synthetically testable (ENC-TSK-
# P12 AC-3) without touching AWS at all.
# ---------------------------------------------------------------------------

def evaluate_activity(
    invocation_sum: Optional[float], *, component_name: str, expected_within_hours: float,
) -> Tuple[str, str, str]:
    """Pure, AWS-free. Returns (state, reason_code, detail)."""
    if invocation_sum is None:
        return FAIL, "no_datapoints", (
            f"ALARM {component_name}: CloudWatch returned no AWS/Lambda Invocations "
            f"datapoints at all within the {expected_within_hours:g}h tolerance window -- "
            f"this schedule has produced zero observed activity in-window (ENC-ISS-667 "
            f"class: a stopped cron is silent without this check)."
        )
    if invocation_sum <= 0:
        return FAIL, "zero_invocations", (
            f"ALARM {component_name}: AWS/Lambda Invocations Sum == {invocation_sum:g} across "
            f"the {expected_within_hours:g}h tolerance window."
        )
    return PASS, "activity_observed", (
        f"OK {component_name}: {invocation_sum:g} invocation(s) observed within the "
        f"{expected_within_hours:g}h tolerance window."
    )


def fetch_invocation_sum(
    cw_client: Any, function_name: str, start: datetime, end: datetime,
) -> Optional[float]:
    """The one AWS call the detector's core logic depends on. Kept tiny and
    swappable so tests can inject a fake client returning a
    GetMetricData-shaped response instead of exercising boto3."""
    period = max(60, int((end - start).total_seconds()))
    resp = cw_client.get_metric_data(
        MetricDataQueries=[{
            "Id": "invocations",
            "MetricStat": {
                "Metric": {
                    "Namespace": "AWS/Lambda",
                    "MetricName": "Invocations",
                    "Dimensions": [{"Name": "FunctionName", "Value": function_name}],
                },
                "Period": period,
                "Stat": "Sum",
            },
            "ReturnData": True,
        }],
        StartTime=start,
        EndTime=end,
    )
    results = resp.get("MetricDataResults", [])
    if not results:
        return None
    values = results[0].get("Values", [])
    if not values:
        return None
    return float(sum(values))


def check_component_liveness(
    cw_client: Any, component_name: str, expected_within_hours: float, *,
    now: Optional[datetime] = None,
    fetch: Callable[..., Optional[float]] = fetch_invocation_sum,
) -> Tuple[str, str, str]:
    now = now or datetime.now(timezone.utc)
    start = now - timedelta(hours=expected_within_hours)
    try:
        total = fetch(cw_client, component_name, start, now)
    except Exception as exc:  # noqa: BLE001
        return UNKNOWN, "cloudwatch_error", f"{component_name}: CloudWatch GetMetricData failed: {exc}"
    return evaluate_activity(total, component_name=component_name, expected_within_hours=expected_within_hours)


# ---------------------------------------------------------------------------
# Live enumeration (--live only)
# ---------------------------------------------------------------------------

@dataclass
class LiveItem:
    name: str
    kind: str  # "events_rule" | "scheduler_schedule"
    plane: str
    state: str
    schedule_expression: Optional[str]
    target_function: Optional[str]


def _infer_plane(name: str) -> str:
    return "gamma" if name.endswith("-gamma") else "prod"


def _function_from_arn(arn: Optional[str]) -> Optional[str]:
    if not arn or ":function:" not in arn:
        return None
    return arn.split(":function:")[-1]


def enumerate_live_rules(events_client: Any, scope_prefixes: Tuple[str, ...]) -> List[LiveItem]:
    items: List[LiveItem] = []
    paginator = events_client.get_paginator("list_rules")
    for page in paginator.paginate():
        for r in page.get("Rules", []):
            name = r.get("Name", "")
            if not name.startswith(scope_prefixes):
                continue
            target_fn = None
            try:
                targets = events_client.list_targets_by_rule(Rule=name).get("Targets", [])
                for t in targets:
                    fn = _function_from_arn(t.get("Arn"))
                    if fn:
                        target_fn = fn
                        break
            except Exception:  # noqa: BLE001
                target_fn = None
            items.append(LiveItem(
                name=name, kind="events_rule", plane=_infer_plane(name),
                state=r.get("State", "UNKNOWN"),
                schedule_expression=r.get("ScheduleExpression"),
                target_function=target_fn,
            ))
    return items


def enumerate_live_schedules(scheduler_client: Any, scope_prefixes: Tuple[str, ...]) -> List[LiveItem]:
    items: List[LiveItem] = []
    paginator = scheduler_client.get_paginator("list_schedules")
    for page in paginator.paginate():
        for s in page.get("Schedules", []):
            name = s.get("Name", "")
            if not name.startswith(scope_prefixes):
                continue
            group = s.get("GroupName", "default")
            try:
                detail = scheduler_client.get_schedule(Name=name, GroupName=group)
            except Exception:  # noqa: BLE001
                detail = {}
            items.append(LiveItem(
                name=name, kind="scheduler_schedule", plane=_infer_plane(name),
                state=detail.get("State", s.get("State", "UNKNOWN")),
                schedule_expression=detail.get("ScheduleExpression"),
                target_function=_function_from_arn((detail.get("Target") or {}).get("Arn")),
            ))
    return items


# ---------------------------------------------------------------------------
# Reconciliation + classification
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    name: str
    kind: str
    plane: str
    state: str
    classification: str
    verdict: str
    detail: str


def classify_and_check(
    live_items: List[LiveItem],
    declared_catalog: Dict[str, DeclaredResource],
    contract: dict,
    devops_owned: Optional[Set[str]],
    legacy_tier_map: Optional[Dict[str, str]],
    *,
    cw_client: Any = None,
    now: Optional[datetime] = None,
) -> List[Finding]:
    findings: List[Finding] = []
    scope_prefixes = tuple(contract["scope_prefixes"]["prefixes"])

    live_by_key = {(i.plane, i.kind, i.name): i for i in live_items}
    rhythm_basenames = set(contract["rhythm_beat_family"]["schedule_name_basenames"])
    tier_to_basename = contract["rhythm_tier_to_schedule_basename"]

    # rhythm beat live states, per plane, keyed by basename -- needed both
    # for the beat-family's own consistency check and for the general
    # "is any tier alive" fallback used by rhythm_absorbed_legacy_family.
    rhythm_states: Dict[str, Dict[str, str]] = {"prod": {}, "gamma": {}}
    for item in live_items:
        if item.kind != "scheduler_schedule":
            continue
        base = item.name[: -len("-gamma")] if item.plane == "gamma" and item.name.endswith("-gamma") else item.name
        if base in rhythm_basenames:
            rhythm_states[item.plane][base] = item.state

    for plane in ("prod", "gamma"):
        states = set(rhythm_states[plane].values())
        if states and len(states) > 1:
            for base, state in rhythm_states[plane].items():
                name = base + _PLANE_SUFFIX[plane]
                findings.append(Finding(
                    name=name, kind="scheduler_schedule", plane=plane, state=state,
                    classification="RHYTHM_BEAT_MIXED_STATE",
                    verdict=FAIL,
                    detail=(
                        f"ALARM {name}: the five rhythm beat schedules do not share a single "
                        f"state on {plane} ({dict(rhythm_states[plane])!r}) -- ENC-TSK-N78's "
                        f"documented pause moves all five together; a split state is not a "
                        f"documented configuration and is treated as a violation, not a "
                        f"partial pass."
                    ),
                ))

    for item in live_items:
        # 1. devops ownership trumps everything.
        if devops_owned is not None and item.target_function in devops_owned:
            findings.append(Finding(
                name=item.name, kind=item.kind, plane=item.plane, state=item.state,
                classification="NOT_APPLICABLE_ON_PLANE",
                verdict=PASS,
                detail=(
                    f"NOT_APPLICABLE_ON_PLANE {item.name}: target {item.target_function!r} is "
                    f"owned by NX-2021-L/devops (infrastructure/devops_lambda_ownership_snapshot.json, "
                    f"ENC-TSK-P15) -- devops's liveness to assert, not enceladus's. This gate still "
                    f"fires (this line), it does not silently skip."
                ),
            ))
            continue

        # 2. rhythm beat family (handled by the consistency pass above; give
        #    each member its own PASS line here unless already flagged mixed).
        if item.kind == "scheduler_schedule":
            base = item.name[: -len("-gamma")] if item.plane == "gamma" and item.name.endswith("-gamma") else item.name
            if base in rhythm_basenames:
                already_flagged = any(
                    f.name == item.name and f.classification == "RHYTHM_BEAT_MIXED_STATE" for f in findings
                )
                if not already_flagged:
                    findings.append(Finding(
                        name=item.name, kind=item.kind, plane=item.plane, state=item.state,
                        classification="DELIBERATELY_PAUSED_RHYTHM_BEAT" if item.state == "DISABLED" else "LIVE_RHYTHM_BEAT",
                        verdict=PASS,
                        detail=(
                            f"{'DELIBERATE' if item.state == 'DISABLED' else 'OK'} {item.name}: rhythm "
                            f"pacemaker beat, ENC-TSK-N78 (RhythmBeatsEnabled); all five beats share "
                            f"state={item.state!r} on {item.plane}."
                        ),
                    ))
                continue

        declared_key = f"{item.plane}:{item.kind}:{item.name}"
        declared = declared_catalog.get(declared_key)
        cross_kind = "scheduler_schedule" if item.kind == "events_rule" else "events_rule"
        cross_key = f"{item.plane}:{cross_kind}:{item.name}"
        cross_declared = declared_catalog.get(cross_key)

        if item.schedule_expression is None and item.kind == "events_rule":
            findings.append(Finding(
                name=item.name, kind=item.kind, plane=item.plane, state=item.state,
                classification="OUT_OF_SCOPE_NOT_SCHEDULED",
                verdict=PASS,
                detail=(
                    f"OUT_OF_SCOPE {item.name}: ScheduleExpression is null (event-pattern rule, "
                    f"not cadence-driven) -- no tolerance window applies. Reported for visibility, "
                    f"never silently dropped."
                ),
            ))
            continue

        # 3. RhythmAbsorbed-gated legacy supersession (structural pattern).
        ral = contract["rhythm_absorbed_legacy_family"]
        if declared is not None and _state_matches_if_pattern(declared.state_prop, ral["cfn_state_if_pattern"]):
            if item.state == "ENABLED":
                pass  # falls through to the normal LIVE cadence check below
            else:
                tier = (legacy_tier_map or {}).get(item.name)
                if tier and tier in tier_to_basename:
                    tier_sched_name = tier_to_basename[tier] + _PLANE_SUFFIX[item.plane]
                    tier_state = rhythm_states[item.plane].get(tier_to_basename[tier])
                    if tier_state == "ENABLED":
                        findings.append(Finding(
                            name=item.name, kind=item.kind, plane=item.plane, state=item.state,
                            classification="LEGACY_SUPERSEDED",
                            verdict=PASS,
                            detail=(
                                f"OK {item.name}: disabled under RhythmAbsorbed, superseded by rhythm "
                                f"tier {tier!r} (backend/lambda/rhythm_cycle/legacy_schedules.py) -- "
                                f"{tier_sched_name} is live ENABLED, so the supersession claim holds."
                            ),
                        ))
                    else:
                        findings.append(Finding(
                            name=item.name, kind=item.kind, plane=item.plane, state=item.state,
                            classification="LEGACY_SUPERSEDED_CONTRADICTION",
                            verdict=FAIL,
                            detail=(
                                f"ALARM {item.name}: disabled under RhythmAbsorbed, claiming supersession "
                                f"by rhythm tier {tier!r}, but {tier_sched_name} is observed "
                                f"{tier_state!r} (not ENABLED) -- the supersession claim is FALSE. This "
                                f"is the exact ENC-ISS-667 mechanism: a legacy schedule disabled because "
                                f"'rhythm now handles it' while rhythm itself is paused, leaving the "
                                f"component silently uncovered by either path."
                            ),
                        ))
                    continue
                else:
                    any_enabled = any(s == "ENABLED" for s in rhythm_states[item.plane].values())
                    if any_enabled:
                        findings.append(Finding(
                            name=item.name, kind=item.kind, plane=item.plane, state=item.state,
                            classification="LEGACY_SUPERSEDED_GENERAL",
                            verdict=PASS,
                            detail=(
                                f"OK {item.name}: disabled under RhythmAbsorbed; no specific rhythm_tier "
                                f"mapping in legacy_schedules.py, but at least one rhythm beat schedule "
                                f"is live ENABLED on {item.plane} -- the pacemaker is not entirely dark. "
                                f"Consider adding a precise tier mapping to legacy_schedules.py."
                            ),
                        ))
                    else:
                        findings.append(Finding(
                            name=item.name, kind=item.kind, plane=item.plane, state=item.state,
                            classification="LEGACY_SUPERSEDED_CONTRADICTION_GENERAL",
                            verdict=FAIL,
                            detail=(
                                f"ALARM {item.name}: disabled under RhythmAbsorbed (no specific "
                                f"rhythm_tier mapping in legacy_schedules.py), and ALL FIVE rhythm beat "
                                f"schedules are observed DISABLED on {item.plane} -- the rhythm pacemaker "
                                f"is entirely dark, so nothing is covering this component. ENC-ISS-667 "
                                f"class contradiction."
                            ),
                        ))
                    continue

        # 4. UnlearningEnabledCond io-HOLD (structural pattern).
        iohold = contract["io_hold_family"]
        if declared is not None and _state_matches_if_pattern(declared.state_prop, iohold["cfn_state_if_pattern"]):
            if item.state == "DISABLED":
                findings.append(Finding(
                    name=item.name, kind=item.kind, plane=item.plane, state=item.state,
                    classification="DELIBERATELY_PAUSED_IO_HOLD",
                    verdict=PASS,
                    detail=(
                        f"DELIBERATE {item.name}: {iohold['citation']} standing io-HOLD "
                        f"(UnlearningEnabled default false) -- expected disabled state."
                    ),
                ))
                continue
            # ENABLED means io re-armed it; falls through to the normal LIVE check.

        # 5. Permanently decommissioned (literal DISABLED + cited comment).
        pdr_entries = contract["permanently_decommissioned_rules"].get("entries", [])
        pdr_match = next((e for e in pdr_entries if e.get("name_contains", "") in item.name), None)
        if pdr_match is not None:
            if item.state == "DISABLED":
                findings.append(Finding(
                    name=item.name, kind=item.kind, plane=item.plane, state=item.state,
                    classification="PERMANENTLY_DECOMMISSIONED",
                    verdict=PASS,
                    detail=f"DELIBERATE {item.name}: permanently retired, {pdr_match['citation']}.",
                ))
            else:
                findings.append(Finding(
                    name=item.name, kind=item.kind, plane=item.plane, state=item.state,
                    classification="PERMANENTLY_DECOMMISSIONED_CONTRADICTION",
                    verdict=FAIL,
                    detail=(
                        f"ALARM {item.name}: declared permanently decommissioned "
                        f"({pdr_match['citation']}) but observed live state is {item.state!r}, not "
                        f"DISABLED -- either it was re-enabled without updating the record, or the "
                        f"declared exception no longer applies."
                    ),
                ))
            continue

        # 6/7. Orphan / undeclared.
        if declared is None:
            if cross_declared is not None:
                findings.append(Finding(
                    name=item.name, kind=item.kind, plane=item.plane, state=item.state,
                    classification="ORPHANED_CROSS_SERVICE_STALE_RESOURCE",
                    verdict=FAIL,
                    detail=(
                        f"ALARM {item.name}: live as a {item.kind} on {item.plane}, but 02-compute.yaml "
                        f"declares no {item.kind} of this name for this plane -- it DOES declare a "
                        f"{cross_declared.kind} of the identical name ({cross_declared.resource_name}). "
                        f"EventBridge Rules and EventBridge Scheduler are different services with "
                        f"independent namespaces, so the same name can exist in both at once. This "
                        f"shape (verified live, ENC-TSK-P12, devops-governance-mart-daily-gamma) is "
                        f"consistent with a resource retained across a Rule->Scheduler migration via "
                        f"DeletionPolicy: Retain. Do not classify this live resource using the OTHER "
                        f"kind's declared rationale -- resolve by deleting the stale resource or "
                        f"declaring it explicitly for what it actually is."
                    ),
                ))
            else:
                findings.append(Finding(
                    name=item.name, kind=item.kind, plane=item.plane, state=item.state,
                    classification="UNDECLARED_LIVE_SCHEDULE",
                    verdict=FAIL,
                    detail=(
                        f"ALARM {item.name}: live {item.kind} on {item.plane}, in scope "
                        f"({scope_prefixes}), declared in NEITHER 02-compute.yaml (any plane-"
                        f"applicable Events::Rule/Scheduler::Schedule) NOR any governed exception "
                        f"family in liveness_contract.json. ENC-TSK-P12 AC-4: a live schedule "
                        f"invisible to every declared source."
                    ),
                ))
            continue

        # 8/9. Declared, and not otherwise exempted.
        if item.state != "ENABLED":
            findings.append(Finding(
                name=item.name, kind=item.kind, plane=item.plane, state=item.state,
                classification="UNRESOLVED_DISABLED",
                verdict=FAIL,
                detail=(
                    f"ALARM {item.name}: declared in 02-compute.yaml but observed DISABLED, and its "
                    f"disablement matches no governed exception family (devops ownership, rhythm beat, "
                    f"RhythmAbsorbed legacy supersession, io-HOLD, permanent decommission). Resolve to "
                    f"a governed exception or re-enable -- ENC-TSK-P12 AC-4 forbids silence here."
                ),
            ))
            continue

        component = item.target_function or item.name
        hours, source_note = expected_tolerance_hours(component, item.schedule_expression, contract)
        if hours is None:
            findings.append(Finding(
                name=item.name, kind=item.kind, plane=item.plane, state=item.state,
                classification="UNRESOLVED_TOLERANCE",
                verdict=UNKNOWN,
                detail=(
                    f"UNKNOWN {item.name}: live, ENABLED, in scope, but no tolerance could be "
                    f"determined ({source_note}). Add an explicit override in "
                    f"liveness_contract.json overrides.entries[{component!r}]."
                ),
            ))
            continue

        if cw_client is None:
            findings.append(Finding(
                name=item.name, kind=item.kind, plane=item.plane, state=item.state,
                classification="LIVE",
                verdict=UNKNOWN,
                detail=(
                    f"UNKNOWN {item.name}: live, ENABLED, tolerance={hours:g}h ({source_note}), but "
                    f"no CloudWatch client was provided -- activity was not checked this run."
                ),
            ))
            continue

        state, _reason, detail = check_component_liveness(cw_client, component, hours, now=now)
        findings.append(Finding(
            name=item.name, kind=item.kind, plane=item.plane, state=item.state,
            classification="LIVE",
            verdict=state,
            detail=f"{detail} (tolerance {source_note})",
        ))

    # ENC-TSK-P12 AC-1/AC-2, unconditional: every component named in
    # overrides.entries (devops-recompute-governance[-gamma],
    # devops-governance-mart[-gamma] -- the exact family this task's defect
    # narrative is about) gets a DIRECT CloudWatch Invocations check here,
    # regardless of what the rule-level classification above concluded.
    # This is deliberate duplication, not an oversight: the rule-level walk
    # above explains WHY a trigger is disabled (and catches the ENC-ISS-667
    # contradiction when a supersession claim is false), but AC-2 requires a
    # detector that does not depend on that reasoning being correct at all --
    # it must observe the FUNCTION's own activity directly. If
    # devops-recompute-governance-backstop-gamma's rule-level classification
    # logic ever had a bug that let a real gap slip through as "explained",
    # this second, independent pass over the actual target function's
    # CloudWatch metric still catches it. Two independently-motivated
    # detectors agreeing is stronger evidence than one detector asked twice.
    if cw_client is not None:
        for component_name, override_entry in contract["overrides"].get("entries", {}).items():
            hours = float(override_entry["expected_activity_within_hours"])
            state, _reason, detail = check_component_liveness(cw_client, component_name, hours, now=now)
            findings.append(Finding(
                name=component_name, kind="lambda_function", plane=_infer_plane(component_name),
                state="N/A",
                classification="LIVE_COMPONENT_DIRECT_CHECK",
                verdict=state,
                detail=f"{detail} (declared override, independent of any rule-level trigger classification)",
            ))

    return findings


def reconcile_declared_not_live(
    declared_catalog: Dict[str, DeclaredResource], live_items: List[LiveItem],
) -> List[str]:
    """Declared in CFN but not observed live -- informational only (not yet
    deployed, or a stale declaration), never a failure. Printed for
    visibility, same convention as verify_lambda_arch_parity.py's
    declared_not_live reporting."""
    live_keys = {f"{i.plane}:{i.kind}:{i.name}" for i in live_items}
    notes = []
    for key, res in sorted(declared_catalog.items()):
        if key not in live_keys:
            notes.append(
                f"{key} ({res.resource_name}): declared in 02-compute.yaml, not observed live -- "
                f"not yet deployed, or plane-conditional and correctly absent."
            )
    return notes


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def run_structural(contract: dict) -> List[str]:
    errors: List[str] = []
    errors += validate_contract_structure(contract)
    if errors:
        return errors  # can't usefully go deeper

    owned, err = load_devops_owned_function_names()
    if owned is None:
        errors.append(f"could not load devops ownership snapshot for reuse: {err}")
    else:
        log(f"reused devops ownership snapshot: {len(owned)} function name(s)")

    tier_map, err = load_legacy_rule_to_tier_map()
    if tier_map is None:
        errors.append(f"could not load legacy schedule inventory for reuse: {err}")
    else:
        log(f"reused legacy schedule inventory: {len(tier_map)} rule(s) with a rhythm_tier mapping")

    catalog, cat_errors = build_declared_catalog()
    errors += cat_errors
    if catalog is not None:
        template_names = ", ".join(str(p.relative_to(REPO_ROOT)) for p in CFN_TEMPLATE_PATHS)
        log(f"parsed {len(catalog)} declared Events::Rule/Scheduler::Schedule instance(s) "
            f"across both planes from {template_names}")

    errors += verify_conditions_present()
    errors += verify_permanently_decommissioned_citations(contract)
    return errors


def run_live(contract: dict, region: str) -> Tuple[List[Finding], List[str], str]:
    """Returns (findings, notes, status). status is one of RECONCILED,
    VIOLATIONS_FOUND, UNKNOWN_NO_LIVE_ACCESS."""
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
    except ImportError:
        return [], ["boto3 not available"], "UNKNOWN_NO_LIVE_ACCESS"

    try:
        session = boto3.Session(region_name=region)
        events_client = session.client("events")
        scheduler_client = session.client("scheduler")
        cw_client = session.client("cloudwatch")
        scope_prefixes = tuple(contract["scope_prefixes"]["prefixes"])
        live_items = enumerate_live_rules(events_client, scope_prefixes) + \
            enumerate_live_schedules(scheduler_client, scope_prefixes)
    except (BotoCoreError, ClientError, NoCredentialsError) as exc:
        return [], [f"live AWS enumeration failed: {exc}"], "UNKNOWN_NO_LIVE_ACCESS"

    owned, _ = load_devops_owned_function_names()
    tier_map, _ = load_legacy_rule_to_tier_map()
    catalog, cat_errors = build_declared_catalog()
    if catalog is None:
        return [], cat_errors, "UNKNOWN_NO_LIVE_ACCESS"

    findings = classify_and_check(
        live_items, catalog, contract, owned, tier_map, cw_client=cw_client,
    )
    notes = reconcile_declared_not_live(catalog, live_items)
    status = "VIOLATIONS_FOUND" if any(f.verdict == FAIL for f in findings) else "RECONCILED"
    return findings, notes, status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="run the full AWS-derived reconciliation")
    parser.add_argument("--region", default=DEFAULT_REGION)
    parser.add_argument("--output", help="write a JSON report to this path")
    args = parser.parse_args()

    contract = load_contract()
    structural_errors = run_structural(contract)
    if structural_errors:
        print("[ERROR] liveness contract structural validation FAILED:")
        for e in structural_errors:
            print(f"  {e}")
    else:
        template_names = ", ".join(str(p.relative_to(REPO_ROOT)) for p in CFN_TEMPLATE_PATHS)
        print(f"[SUCCESS] liveness contract structural validation passed "
              f"({CONTRACT_PATH.relative_to(REPO_ROOT)}, devops ownership snapshot, "
              f"legacy schedule inventory, {template_names} all consistent).")

    exit_code = 1 if structural_errors else 0
    report: Dict[str, Any] = {"structural_errors": structural_errors}

    if args.live:
        findings, notes, status = run_live(contract, args.region)
        report["live_status"] = status
        report["live_findings"] = [f.__dict__ for f in findings]
        report["live_notes"] = notes

        if status == "UNKNOWN_NO_LIVE_ACCESS":
            print(f"[UNKNOWN] --live requested but live reconciliation did not run: {notes}")
        else:
            counts: Dict[str, int] = {}
            for f in findings:
                counts[f.verdict] = counts.get(f.verdict, 0) + 1
            print(f"[INFO] live reconciliation: {len(findings)} scheduled component(s) evaluated "
                  f"-- {counts}")
            for f in findings:
                tag = {"pass": "[OK]", "fail": "[FAIL]", "unknown": "[UNKNOWN]"}[f.verdict]
                print(f"  {tag} {f.classification:40s} {f.plane:5s} {f.name}: {f.detail}")
            for n in notes:
                print(f"  [DECLARED-NOT-LIVE] {n}")
            if status == "VIOLATIONS_FOUND":
                exit_code = 1

    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
