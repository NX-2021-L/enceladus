#!/usr/bin/env python3
"""ENC-TSK-Q05 AC-3 (ENC-ISS-778 P0): post-deploy smoke test with automatic
alias rollback.

ENC-ISS-778's mcp.jreese.net P0 shipped an unservable artifact and returned
502 on every route for hours before a human noticed -- nothing after the
alias flip ever checked that the function actually worked. This script is
that check: after _deploy.yml's "Deploy Lambda functions" step updates the
'live' alias, probe each deployed function's public endpoint (data-driven --
see PROBE_TABLE) and, if it is not healthy after a few retries (a cold start
is not an outage), automatically restore the alias to the version captured
immediately before the deploy and fail the run.

Two subcommands, both invoked from the .guard-tools sparse checkout like the
AC-2 guard:

  capture  -- run BEFORE "Deploy Lambda functions". Records each deploy
              target's current 'live' alias FunctionVersion (nothing to roll
              back to if this is skipped -- see run_capture()/main()).
              ENC-TSK-Q05 review finding (critical): get_live_alias_version()
              MUST distinguish a genuine "no 'live' alias exists yet"
              (ResourceNotFoundException / "Function not found" -- a real
              bootstrap case, safe to treat as "nothing to capture") from
              every OTHER AWS CLI failure (throttling, AccessDenied, a
              timeout, ...). Collapsing both into the same "nothing
              captured" result would let a capture-time hiccup silently turn
              the post-deploy smoke test into a no-op that still exits 0 --
              run_check() would then see no previous_version, return
              "no_previous_version" WITHOUT ever calling the HTTP probe, and
              the run would pass. So: a genuine bootstrap -> logged as
              "[none] ... (bootstrap case)"; any OTHER error -> the capture
              step FAILS CLOSED (non-zero exit), blocking the deploy job
              before "Deploy Lambda functions" even runs, rather than
              silently proceeding on an unverified alias state.
  check    -- run AFTER the alias update. Probes every deployed function
              that has a PROBE_TABLE entry; on failure, rolls the alias back
              to the version `capture` recorded and verifies recovery;
              always fails the run (exit 1) when a rollback happened,
              whether or not recovery verified -- a rollback firing at all
              means the deploy was bad and needs investigation.

Both subcommands resolve "which Lambda functions did this run touch" the
same way (resolve_deployed_function_names()), from the SAME two already-
resolved _deploy.yml resolve-job outputs (function_name_map_json,
version_ids_json) -- no new resolve-job output is needed for this AC.

Fail-closed / no-op semantics (the whole point, see spawn_task-style
requirements this backstops):
  - No PROBE_TABLE entry for a deployed function -> "no_probe": a clean
    no-op for that function, not a failure and not counted as a pass.
  - PROBE_TABLE has no entry for the deployed name, but the name is that
    KNOWN incident-surface function under a different environment suffix
    (e.g. a main-lane workflow_dispatch to v4-gamma deploying
    "enceladus-mcp-code-gamma", which PROBE_TABLE does not key) ->
    "no_probe_env_variant": still a clean, non-failing no-op (there is no
    known health URL for that environment to probe), but reported and
    ::warning::-annotated distinctly from a plain "no_probe" so a
    gamma-targeted run through this lane does not read identically to a
    fully-verified prod run in the job summary. See PROBE_TABLE /
    _base_function_name() below.
  - No captured previous alias version for a function that DOES have a
    probe entry -> "no_previous_version": also a clean no-op (cannot roll
    back to nothing), reported distinctly so it is never mistaken for a
    verified-healthy pass.
  - Probe unhealthy + rollback succeeds + recovery verified -> "rolled_back":
    still fails the run (exit 1) -- the point is "shipped a broken thing and
    caught it automatically", not "shipped a broken thing, quietly fine now".
  - Probe unhealthy + rollback itself fails -> "rollback_failed": fails the
    run with the AWS error surfaced.
  - --dry-run performs no AWS mutation (no update-alias call) and no
    swallowing of a would-be failure into a false "pass": it always reports
    what it *would* have done and exits 0, since a dry run is explicitly a
    preview, never an enforcement gate.

Run: post_deploy_smoke.py capture --function-name-map-json ... --version-ids-json ... --region ...
     post_deploy_smoke.py check   --function-name-map-json ... --version-ids-json ... \\
                                   --previous-alias-versions-json ... --region ... [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Probe table -- data-driven, NOT hardcoded inline to one function.
# function name (the deployed Lambda name, matching function_name_map's
# values) -> ProbeTarget(base_url, probes). Extend this table as more
# functions grow a post-deploy health surface.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProbeSpec:
    path: str
    healthy_status: Tuple[int, ...]


# ENC-TSK-Q09 review finding (critical): get_function_url_qualifier()'s live
# `aws lambda get-function-url-config` call needs lambda:GetFunctionUrlConfig,
# a permission NOT granted to GitHubActions-V4Gamma-DeployRole (the role
# _deploy.yml actually assumes to run `post_deploy_smoke.py check` for
# v4-gamma) and, as far as this repo codifies IAM, not to the v3-prod/v4-prod
# deploy roles either (those roles are not codified in this repo at all --
# see infrastructure/cloudformation/04-github-roles.yaml). A dynamic call
# that categorically blocks rollback whenever it cannot get an answer would
# have silently disabled automatic recovery for EVERY PROBE_TABLE function
# the first time a probe legitimately failed, including enceladus-mcp-code,
# which has always been alias-qualified and rolled back successfully before
# ENC-TSK-Q09 existed.
#
# So each ProbeTarget carries its own already-established classification
# instead of always asking AWS live:
#   ALIAS_QUALIFIED       -- proven/known to route through an alias (e.g.
#                            "live") -- rollback_fn is called directly, the
#                            same as every pre-ENC-TSK-Q09 caller; the AWS
#                            call is never made and no new IAM grant is
#                            needed.
#   UNQUALIFIED_CONFIRMED -- proven to serve $LATEST directly (this is
#                            enceladus-mcp-streamable, established during the
#                            ENC-ISS-782 incident) -- rollback is refused
#                            without ever calling AWS either.
#   VERIFY_AT_RUNTIME     -- not yet classified (a future PROBE_TABLE
#                            addition that hasn't been proven either way) --
#                            falls back to the live qualifier_fn() check, and
#                            an undetermined result (AccessDenied, etc.)
#                            fails closed, refusing the rollback. This is the
#                            ONLY state that depends on
#                            lambda:GetFunctionUrlConfig being granted, so a
#                            future entry that needs it must provision that
#                            grant for whichever deploy role runs `check`
#                            against it.
QUALIFIER_ALIAS_QUALIFIED = "alias_qualified"
QUALIFIER_UNQUALIFIED_CONFIRMED = "unqualified_confirmed"
QUALIFIER_VERIFY_AT_RUNTIME = "verify_at_runtime"


@dataclass(frozen=True)
class ProbeTarget:
    base_url: str
    probes: Tuple[ProbeSpec, ...]
    qualifier_state: str = QUALIFIER_VERIFY_AT_RUNTIME


PROBE_TABLE: Dict[str, ProbeTarget] = {
    # enceladus-mcp-code / mcp.jreese.net: the ENC-ISS-778 incident surface.
    # Both routes 502'd during the incident; both must resolve to their
    # normal (non-502) status for the function to count as healthy.
    #
    # ENC-TSK-Q05 review finding (major): this table is keyed by the
    # PRODUCTION Lambda name only. main's own _deploy.yml workflow_dispatch
    # input schema also allows target_environment=v4-gamma, whose deployed
    # function name is "enceladus-mcp-code-gamma" (infrastructure/
    # cloudformation/02-compute.yaml) -- a name this table does not key, and
    # there is no known reachable health URL for gamma to add a real entry
    # for. resolve_deployed_function_names() would hand run_function_smoke()
    # that gamma name; without the _base_function_name() handling below, the
    # lookup misses and reports a plain "no_probe" -- indistinguishable in
    # the job summary from a function that legitimately has no health
    # surface at all. See "no_probe_env_variant" in run_function_smoke().
    "enceladus-mcp-code": ProbeTarget(
        base_url="https://mcp.jreese.net",
        probes=(
            ProbeSpec(path="/.well-known/oauth-protected-resource", healthy_status=(200,)),
            ProbeSpec(path="/", healthy_status=(401,)),
        ),
        # Always alias-qualified: ENC-ISS-418 provisioned GetAlias/
        # CreateAlias/UpdateAlias specifically so _deploy.yml can advance the
        # 'live' alias, and every deploy of this function goes through it.
        # No live AWS call needed to confirm that.
        qualifier_state=QUALIFIER_ALIAS_QUALIFIED,
    ),
    # ENC-TSK-Q09 (ENC-ISS-782 P0): enceladus-mcp-streamable is the actual
    # incident surface (mcp.jreese.net's Function URL, distinct from
    # enceladus-mcp-code's own) -- it must be probed directly by its own
    # Function URL rather than represented via "enceladus-mcp-code", which
    # it is not. Same healthy signature as mcp_code (both serve the same
    # MCP server runtime, just via a different Lambda/URL). This function's
    # Function URL Qualifier is null (serves $LATEST directly, see
    # get_function_url_qualifier() / run_function_smoke() below) -- an
    # alias rollback CANNOT restore it; that was proven during the
    # incident (update-alias from 15 back to 13 succeeded, endpoint stayed
    # 502 on three probes; only update-function-code fixed it).
    "enceladus-mcp-streamable": ProbeTarget(
        base_url="https://4yhnhvq64ek34a2npdgbmjbp2m0wxjil.lambda-url.us-west-2.on.aws",
        probes=(
            ProbeSpec(path="/.well-known/oauth-protected-resource", healthy_status=(200,)),
            ProbeSpec(path="/", healthy_status=(401,)),
        ),
        # Confirmed unqualified during the incident itself -- no live AWS
        # call needed (or, notably, permitted: the deploy roles that run
        # `check` do not grant lambda:GetFunctionUrlConfig for this
        # function either -- see QUALIFIER_UNQUALIFIED_CONFIRMED above).
        qualifier_state=QUALIFIER_UNQUALIFIED_CONFIRMED,
    ),
}


def _base_function_name(function_name: str, environment_suffix: str) -> str:
    """Strip a non-empty, known environment suffix (e.g. "-gamma", from
    _deploy.yml resolve job's `environment_suffix` output) from a deployed
    Lambda name to recover the PROBE_TABLE's base key, e.g.
    "enceladus-mcp-code-gamma" -> "enceladus-mcp-code". Returns
    `function_name` unchanged if there is no suffix to strip or it does not
    match."""
    if environment_suffix and function_name.endswith(environment_suffix):
        return function_name[: -len(environment_suffix)]
    return function_name


# ---------------------------------------------------------------------------
# Pure decision core
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SmokeOutcome:
    function_name: str
    status: str  # see _FAILING_STATUSES below for the set that fails the run
    detail: str


# Outcomes that must fail the run (exit 1). 'healthy', 'no_probe',
# 'no_probe_env_variant', and 'no_previous_version' are all clean,
# non-failing outcomes -- see the module docstring for why 'rolled_back'
# still fails even though the rollback itself succeeded.
#
# ENC-TSK-Q09 (ENC-ISS-782 P0): 'rollback_impossible_unqualified_url' and
# 'rollback_impossible_qualifier_unknown' are the two new outcomes for a
# function whose Function URL Qualifier is unqualified (serves $LATEST
# directly) or could not be determined -- see run_function_smoke() /
# get_function_url_qualifier(). Both fail the run: an alias rollback is
# either PROVEN ineffective for that function (this incident: update-alias
# from 15 back to 13 succeeded and the endpoint stayed 502 on three probes)
# or its safety could not be confirmed, and this script must never attempt
# -- or claim to have performed -- a rollback in either case.
#
# Review finding (critical): 'rollback_impossible_qualifier_unknown' is
# reachable ONLY for a ProbeTarget still classified
# QUALIFIER_VERIFY_AT_RUNTIME (see the ProbeTarget/qualifier_state comment
# above PROBE_TABLE) -- a target already classified
# QUALIFIER_ALIAS_QUALIFIED never calls the live AWS check that produces
# this outcome, so an unprovisioned lambda:GetFunctionUrlConfig grant on the
# deploy role cannot silently disable rollback for a function (like
# enceladus-mcp-code) that has always been alias-qualified.
_FAILING_STATUSES = frozenset({
    "rollback_failed",
    "rollback_unverified",
    "rolled_back",
    "rollback_impossible_unqualified_url",
    "rollback_impossible_qualifier_unknown",
})


def evaluate_probe_results(results: Dict[str, Optional[int]], target: ProbeTarget) -> bool:
    """results: probe path -> observed status code (None if the request
    itself failed/raised). True iff EVERY probe's observed status is in its
    own healthy_status set."""
    return all(results.get(spec.path) in spec.healthy_status for spec in target.probes)


def resolve_deployed_function_names(
    function_name_map: Dict[str, str], version_ids: Dict[str, str]
) -> List[str]:
    """The flat, de-duplicated, order-preserving list of deployed Lambda
    function names this run touched -- mirrors the deploy step's own
    fn -> mapped_name(s) expansion (ENC-ISS-398 comma-list support), driven
    by version_ids (the set this run actually resolved artifacts for), not
    the full function_name_map (which may name functions this run never
    touched)."""
    names: List[str] = []
    for fn in sorted(version_ids):
        mapped = (function_name_map.get(fn) or "").strip()
        if not mapped:
            continue
        for name in (n.strip() for n in mapped.split(",")):
            if name and name not in names:
                names.append(name)
    return names


def run_function_smoke(
    function_name: str,
    previous_version: Optional[str],
    probe_fn: Callable[[ProbeTarget], bool],
    rollback_fn: Callable[[str, str], Tuple[bool, str]],
    dry_run: bool = False,
    environment_suffix: str = "",
    qualifier_fn: Callable[[str], Tuple[Optional[str], Optional[str]]] = lambda name: ("live", None),
) -> SmokeOutcome:
    """Per-function decision pipeline. probe_fn(target) -> True/False (already
    retried with backoff by the caller's chosen implementation -- see
    probe_target() below for the production one). rollback_fn(function_name,
    previous_version) -> (success, message), wrapping the actual
    update-alias call; never invoked when dry_run is set. environment_suffix
    (e.g. "-gamma") is used only to distinguish "no_probe" (a function that
    legitimately has no health surface) from "no_probe_env_variant" (the
    KNOWN incident-surface function, deployed under a different
    environment's name, that PROBE_TABLE does not key -- see
    _base_function_name()).

    qualifier_fn(function_name) -> (qualifier, error) (ENC-TSK-Q09,
    ENC-ISS-782): reports this function's Function URL Qualifier --
    "" (falsy) means the URL is UNQUALIFIED and serves $LATEST directly, a
    shape an alias rollback CANNOT restore (proven during the incident: an
    update-alias call succeeds but the endpoint stays unhealthy, because the
    URL never routes through the alias pointer at all). error carries an
    AWS error string when the qualifier could not be determined. Called
    ONLY when target.qualifier_state is QUALIFIER_VERIFY_AT_RUNTIME AND a
    rollback would otherwise be attempted (a healthy probe, a dry run, or a
    target already classified as QUALIFIER_ALIAS_QUALIFIED /
    QUALIFIER_UNQUALIFIED_CONFIRMED never reaches it -- see
    get_function_url_qualifier() for the production implementation and the
    ProbeTarget/qualifier_state comment above PROBE_TABLE for why most
    entries should NOT rely on this live call). Defaults to a fixed
    alias-qualified result so every EXISTING caller that does not pass this
    argument keeps exercising the normal alias-rollback path unchanged."""
    target = PROBE_TABLE.get(function_name)
    if target is None:
        base_name = _base_function_name(function_name, environment_suffix)
        if base_name != function_name and base_name in PROBE_TABLE:
            return SmokeOutcome(
                function_name, "no_probe_env_variant",
                f"no PROBE_TABLE entry for {function_name!r}, but its base name "
                f"{base_name!r} IS in PROBE_TABLE -- this environment's deployed "
                "function name is a variant PROBE_TABLE does not (yet) cover, so "
                "this deploy shipped WITHOUT any health verification, unlike a "
                "plain 'no_probe' function that legitimately has none to give",
            )
        return SmokeOutcome(function_name, "no_probe", "no PROBE_TABLE entry for this function -- skipped")
    if not previous_version:
        return SmokeOutcome(
            function_name, "no_previous_version",
            "no captured pre-deploy 'live' alias version -- nothing to roll back to, skipped",
        )

    if probe_fn(target):
        return SmokeOutcome(function_name, "healthy", "post-deploy probe(s) passed")

    if dry_run:
        return SmokeOutcome(
            function_name, "unhealthy_dry_run",
            f"probe(s) failed; --dry-run, so no alias mutation was performed "
            f"(would have rolled back to live:{previous_version})",
        )

    # ENC-TSK-Q09 (ENC-ISS-782 P0), tightened by review finding (critical):
    # determine whether an alias rollback can even work for this function
    # BEFORE attempting one -- but only ASK AWS when this target's shape
    # hasn't already been established (QUALIFIER_VERIFY_AT_RUNTIME). A
    # target already classified as QUALIFIER_ALIAS_QUALIFIED or
    # QUALIFIER_UNQUALIFIED_CONFIRMED never calls qualifier_fn at all, so
    # neither depends on lambda:GetFunctionUrlConfig being granted to
    # whichever deploy role runs `check` -- a permission this PR does not
    # provision on any deploy role. Checked here, not earlier, so a healthy
    # probe or a dry run never pays for (or can be blocked by) this extra
    # AWS call either.
    if target.qualifier_state == QUALIFIER_UNQUALIFIED_CONFIRMED:
        return SmokeOutcome(
            function_name, "rollback_impossible_unqualified_url",
            "probe(s) failed; this function's Function URL is already known "
            "to have NO alias Qualifier (it serves $LATEST directly, per "
            "PROBE_TABLE's qualifier_state -- no live check was needed or "
            "performed) -- an alias rollback is PROVEN ineffective for this "
            "shape (ENC-ISS-782: update-alias from 15 back to 13 succeeded "
            "and the endpoint stayed 502 on three probes; only "
            "update-function-code restored it). Automatic rollback is NOT "
            "implemented for this case, to avoid silently 'succeeding' at "
            "an alias mutation that does not change what the Function URL "
            "serves -- restore service manually with update-function-code "
            "against the previously-good artifact and investigate "
            "immediately.",
        )

    if target.qualifier_state == QUALIFIER_VERIFY_AT_RUNTIME:
        qualifier, qual_err = qualifier_fn(function_name)
        if qual_err is not None:
            return SmokeOutcome(
                function_name, "rollback_impossible_qualifier_unknown",
                f"probe(s) failed; this function's Function URL shape is not "
                f"yet classified in PROBE_TABLE (qualifier_state="
                f"QUALIFIER_VERIFY_AT_RUNTIME) and the live check to "
                f"determine whether an alias rollback can restore service "
                f"failed, so NO rollback was attempted: {qual_err}. Either "
                f"provision lambda:GetFunctionUrlConfig for the deploy role "
                f"that ran this check, or classify this function's "
                f"qualifier_state explicitly once its shape is known. "
                f"Investigate and restore manually if needed.",
            )
        if qualifier is None:
            # Review finding (info): distinct message from the "" case just
            # below -- "no Function URL configured at all" is not the same
            # fact as "URL exists but is unqualified", even though both are
            # refused the same way (this should not occur in practice, since
            # every PROBE_TABLE entry's base_url IS a Function URL, but the
            # message must not assert something false if it ever does).
            return SmokeOutcome(
                function_name, "rollback_impossible_unqualified_url",
                "probe(s) failed; a live check found this function has NO "
                "Function URL configured at all -- there is nothing an "
                "alias rollback could restore. Automatic rollback is NOT "
                "implemented for this case -- investigate and restore "
                "manually.",
            )
        if not qualifier:
            return SmokeOutcome(
                function_name, "rollback_impossible_unqualified_url",
                "probe(s) failed; a live check found this function's "
                "Function URL has NO alias Qualifier (it serves $LATEST "
                "directly) -- an alias rollback is PROVEN ineffective for "
                "this shape (ENC-ISS-782: update-alias from 15 back to 13 "
                "succeeded and the endpoint stayed 502 on three probes; "
                "only update-function-code restored it). Automatic "
                "rollback is NOT implemented for this case, to avoid "
                "silently 'succeeding' at an alias mutation that does not "
                "change what the Function URL serves -- restore service "
                "manually with update-function-code against the "
                "previously-good artifact and investigate immediately.",
            )
        # qualifier confirmed truthy (alias-qualified) via the live check --
        # fall through to the normal rollback attempt below.

    # target.qualifier_state == QUALIFIER_ALIAS_QUALIFIED, or
    # QUALIFIER_VERIFY_AT_RUNTIME with a live-confirmed alias-qualified URL.
    rb_ok, rb_detail = rollback_fn(function_name, previous_version)
    if not rb_ok:
        return SmokeOutcome(
            function_name, "rollback_failed",
            f"probe(s) failed AND automatic rollback to live:{previous_version} also failed: {rb_detail}",
        )

    if probe_fn(target):
        return SmokeOutcome(
            function_name, "rolled_back",
            f"probe(s) failed; automatically rolled back to live:{previous_version} "
            "and recovery verified -- this deploy must be investigated",
        )
    return SmokeOutcome(
        function_name, "rollback_unverified",
        f"probe(s) failed; rolled back to live:{previous_version} but the "
        "recovery probe is STILL unhealthy -- investigate immediately",
    )


def decide_exit_code(outcomes: Sequence[SmokeOutcome]) -> int:
    return 1 if any(o.status in _FAILING_STATUSES for o in outcomes) else 0


# ---------------------------------------------------------------------------
# Impure edges: HTTP probing (with retry/backoff) and AWS alias I/O.
# ---------------------------------------------------------------------------

def _http_status(url: str, timeout: float = 10.0) -> Optional[int]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        # A non-2xx response (e.g. the expected 401) still reaches here with
        # a real status code -- that's a successful probe, not a failure.
        return e.code
    except Exception:
        return None


def probe_target(
    target: ProbeTarget,
    attempts: int = 4,
    backoff_seconds: Sequence[float] = (2, 4, 8),
    fetcher: Callable[[str], Optional[int]] = _http_status,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> bool:
    """Retries the FULL probe set up to `attempts` times with backoff
    between attempts, because a cold start is not an outage. Returns True
    the first time every probe in `target` is healthy in the same attempt."""
    for i in range(attempts):
        results = {spec.path: fetcher(f"{target.base_url}{spec.path}") for spec in target.probes}
        if evaluate_probe_results(results, target):
            return True
        if i < attempts - 1:
            sleep_fn(backoff_seconds[min(i, len(backoff_seconds) - 1)])
    return False


# Markers a genuine "no 'live' alias exists" error carries -- the same
# shape assert_artifact_arch_matches_functions.py's _is_not_provisioned()
# discriminates for get-function-configuration. ONLY these mean "bootstrap
# case, nothing to capture"; every other failure must fail closed instead
# of being silently treated the same way (ENC-TSK-Q05 review finding,
# critical -- see module docstring).
_NOT_PROVISIONED_MARKERS = ("ResourceNotFoundException", "Function not found")

# Same transient-error marker list as _deploy.yml's own run_with_retry() /
# assert_artifact_arch_matches_functions.py's _TRANSIENT_MARKERS, for this
# same AWS Lambda API surface -- a throttle blip during capture must be
# retried, not immediately escalated to a hard capture failure.
_TRANSIENT_MARKERS = (
    "TooManyRequestsException", "ThrottlingException", "Throttling",
    "ResourceConflictException", "update is in progress",
    "Rate exceeded", "RequestTimeout", "ServiceException",
    "InternalFailure", "SlowDown",
)


def _is_not_provisioned(err: Optional[str]) -> bool:
    return bool(err) and any(marker in err for marker in _NOT_PROVISIONED_MARKERS)


def _run(
    cmd: List[str],
    attempts: int = 4,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> Tuple[Optional[str], Optional[str]]:
    """Runs an AWS CLI command with bounded retry/backoff on transient
    errors (see _TRANSIENT_MARKERS). A non-transient error -- including a
    genuine "not provisioned" one, which callers discriminate via
    _is_not_provisioned() -- returns immediately without retrying."""
    last_err: Optional[str] = None
    for i in range(1, attempts + 1):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except Exception as exc:  # noqa: BLE001
            return None, f"exception invoking {' '.join(cmd)}: {exc}"
        if result.returncode == 0:
            return result.stdout, None
        err = (result.stderr or "").strip() or f"exit {result.returncode}"
        last_err = err
        if i == attempts or not any(marker in err for marker in _TRANSIENT_MARKERS):
            return None, err
        sleep_fn(2 ** i)
    return None, last_err


def get_live_alias_version(function_name: str, region: str) -> Tuple[Optional[str], Optional[str]]:
    """Returns (version, error).

    version is the 'live' alias's current FunctionVersion, or None if
    either genuinely absent OR an error occurred (check `error` to tell
    which).

    error is None for a CLEAN result -- either the alias was found, or it
    is genuinely absent (ResourceNotFoundException / "Function not found":
    a function that has never had a 'live' alias yet is a bootstrapping
    case, not a defect). For any OTHER failure (throttling exhausted,
    AccessDenied, a timeout, an unparseable response, ...), error carries
    the AWS error text -- callers MUST treat that as a capture FAILURE, not
    as "nothing to capture": collapsing the two is exactly the ENC-TSK-Q05
    review finding this return shape fixes (a capture-time hiccup silently
    turning the post-deploy smoke test into a no-op that still exits 0)."""
    out, err = _run([
        "aws", "lambda", "get-alias",
        "--function-name", function_name,
        "--name", "live",
        "--region", region,
        "--output", "json",
    ])
    if out is None:
        if _is_not_provisioned(err):
            return None, None
        return None, err or "get-alias failed with no output and no error detail"
    try:
        version = json.loads(out).get("FunctionVersion")
    except json.JSONDecodeError as exc:
        return None, f"could not parse get-alias JSON output: {exc}"
    return version or None, None


def get_function_url_qualifier(function_name: str, region: str) -> Tuple[Optional[str], Optional[str]]:
    """Returns (qualifier, error) (ENC-TSK-Q09, ENC-ISS-782 P0).

    qualifier is the Function URL config's `Qualifier` field: an alias name
    (e.g. "live") when the URL routes through an alias -- the shape an
    alias rollback can actually restore -- or "" (empty string) when the
    URL is UNQUALIFIED and serves $LATEST directly, bypassing the alias
    pointer entirely. This is the exact shape that made
    enceladus-mcp-streamable's ENC-ISS-782 outage un-rollback-able via
    update-alias: the alias mutation itself succeeds (this function's
    return contract has no way to represent "succeeded but pointless"), but
    nothing the Function URL serves ever changes. qualifier is None only
    when this function has no Function URL configured at all (a genuine
    "not applicable" case -- every PROBE_TABLE entry's base_url IS a
    Function URL, so this should not occur for a function this is called
    for, but is handled the same way get_live_alias_version() handles a
    genuinely absent alias, rather than being conflated with an error).

    error is None for a CLEAN result (alias-qualified, unqualified, or no
    URL configured). For any OTHER failure (throttling exhausted,
    AccessDenied, a timeout, unparseable output), error carries the AWS
    error text and callers MUST treat that as "cannot safely determine
    whether a rollback will work" -- never silently assume alias-qualified
    and attempt a rollback that may be exactly the proven-ineffective no-op
    this function guards against."""
    out, err = _run([
        "aws", "lambda", "get-function-url-config",
        "--function-name", function_name,
        "--region", region,
        "--output", "json",
    ])
    if out is None:
        if _is_not_provisioned(err):
            return None, None
        return None, err or "get-function-url-config failed with no output and no error detail"
    try:
        qualifier = json.loads(out).get("Qualifier", "") or ""
    except json.JSONDecodeError as exc:
        return None, f"could not parse get-function-url-config JSON output: {exc}"
    return qualifier, None


def aws_rollback_alias(function_name: str, previous_version: str, region: str) -> Tuple[bool, str]:
    _out, err = _run([
        "aws", "lambda", "update-alias",
        "--function-name", function_name,
        "--name", "live",
        "--function-version", previous_version,
        "--region", region,
    ])
    if err is None:
        return True, f"live alias restored to version {previous_version}"
    return False, err


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _common_target_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--function-name-map-json", required=True)
    parser.add_argument("--version-ids-json", required=True)
    parser.add_argument("--region", default="us-west-2")


def run_capture(
    function_name_map: Dict[str, str], version_ids: Dict[str, str], region: str
) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Returns (captured, errors). captured maps function name -> its
    pre-deploy 'live' alias FunctionVersion, for every function that has
    one. errors maps function name -> AWS error text, for every function
    whose get_live_alias_version() call failed for a reason OTHER than a
    genuine "no alias yet" bootstrap case -- callers MUST treat a non-empty
    `errors` as a capture failure, never silently proceed as if those
    functions were clean bootstraps (ENC-TSK-Q05 review finding, critical)."""
    captured: Dict[str, str] = {}
    errors: Dict[str, str] = {}
    for name in resolve_deployed_function_names(function_name_map, version_ids):
        version, err = get_live_alias_version(name, region)
        if err is not None:
            errors[name] = err
            continue
        if version:
            captured[name] = version
    return captured, errors


def run_check(
    function_name_map: Dict[str, str],
    version_ids: Dict[str, str],
    previous_versions: Dict[str, str],
    region: str,
    dry_run: bool,
    environment_suffix: str = "",
) -> List[SmokeOutcome]:
    deployed = resolve_deployed_function_names(function_name_map, version_ids)

    def rollback_fn(name: str, version: str) -> Tuple[bool, str]:
        return aws_rollback_alias(name, version, region)

    def qualifier_fn(name: str) -> Tuple[Optional[str], Optional[str]]:
        return get_function_url_qualifier(name, region)

    outcomes = [
        run_function_smoke(
            name, previous_versions.get(name), probe_target, rollback_fn,
            dry_run=dry_run, environment_suffix=environment_suffix,
            qualifier_fn=qualifier_fn,
        )
        for name in deployed
    ]
    return outcomes


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    capture_p = sub.add_parser("capture", help="Capture each deploy target's pre-deploy 'live' alias version.")
    _common_target_args(capture_p)

    check_p = sub.add_parser("check", help="Probe each deployed function; roll back + fail on unhealthy.")
    _common_target_args(check_p)
    check_p.add_argument("--previous-alias-versions-json", required=True)
    check_p.add_argument("--dry-run", action="store_true", help="Probe only; never mutate an alias.")
    check_p.add_argument(
        "--environment-suffix", default="",
        help="This run's resolved environment suffix (e.g. '-gamma'), from "
        "_deploy.yml resolve job's environment_suffix output -- used only "
        "to report 'no_probe_env_variant' distinctly from a plain 'no_probe'.",
    )

    args = parser.parse_args(argv)

    try:
        fn_map = json.loads(args.function_name_map_json)
        version_ids = json.loads(args.version_ids_json)
    except json.JSONDecodeError as exc:
        print(f"::error::could not parse function-name-map/version-ids JSON: {exc}", file=sys.stderr)
        return 2

    if args.command == "capture":
        captured, errors = run_capture(fn_map, version_ids, args.region)
        deployed = resolve_deployed_function_names(fn_map, version_ids)
        for name in deployed:
            if name in errors:
                print(
                    f"::error::{name}: could not capture pre-deploy 'live' alias "
                    f"version (NOT a bootstrap case -- an unexpected AWS error): "
                    f"{errors[name]}",
                    file=sys.stderr,
                )
            elif name in captured:
                print(f"  captured {name}: live={captured[name]}")
            else:
                print(f"  [none] {name}: no existing 'live' alias (bootstrap case) -- nothing to capture")
        print(json.dumps(captured))
        if errors:
            print(
                f"::error::Capture pre-deploy alias versions FAILED for "
                f"{len(errors)} function(s): {', '.join(sorted(errors))} -- failing "
                "closed rather than silently treating an unexplained AWS error the "
                "same as a legitimate bootstrap case (ENC-ISS-778 P0 class: a "
                "swallowed capture failure would let the post-deploy smoke probe "
                "skip silently via 'no_previous_version'). Investigate and re-run.",
                file=sys.stderr,
            )
            return 1
        return 0

    # check
    try:
        previous_versions = json.loads(args.previous_alias_versions_json)
    except json.JSONDecodeError as exc:
        print(f"::error::could not parse previous-alias-versions JSON: {exc}", file=sys.stderr)
        return 2

    outcomes = run_check(
        fn_map, version_ids, previous_versions, args.region, args.dry_run,
        environment_suffix=args.environment_suffix,
    )
    if not outcomes:
        print("No deployed functions to smoke-test -- skipping.")
        return 0

    for o in outcomes:
        if o.status in _FAILING_STATUSES:
            stream, prefix = sys.stderr, "::error::"
        elif o.status == "no_probe_env_variant":
            # Non-failing, but must not look identical to a plain "no_probe"
            # (a function with no health surface) or a verified pass in the
            # job summary -- see PROBE_TABLE / run_function_smoke().
            stream, prefix = sys.stderr, "::warning::"
        else:
            stream, prefix = sys.stdout, "  "
        print(f"{prefix}{o.function_name} [{o.status}]: {o.detail}", file=stream)

    rc = decide_exit_code(outcomes)
    if rc != 0:
        failing = [o.function_name for o in outcomes if o.status in _FAILING_STATUSES]
        print(
            f"::error::Post-deploy smoke test FAILED for: {', '.join(failing)} -- "
            "this deploy must not be treated as successful (ENC-ISS-778 P0 class).",
            file=sys.stderr,
        )
    else:
        print("Post-deploy smoke test passed (or nothing to probe).")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
