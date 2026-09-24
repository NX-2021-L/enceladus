#!/usr/bin/env python3
"""Five-point arm64 validation harness (ENC-TSK-O88, child of ENC-FTR-138 / ENC-PLN-086).

Implements BRD DOC-56CFA21523C1 section 8, "Definition of Validated and UAT'd",
as a reusable, re-runnable, machine-readable predicate -- so ENC-TSK-O89 (26
gamma twins) and ENC-TSK-O90 (Category A) can stamp its output as acceptance
evidence instead of re-deriving the definition ad hoc.

WHY THIS REPLACES THE OLD CRITERION
-----------------------------------------------------------------------------
The blueprint's original Phase 0 exit criterion -- "all Lambda functions
reporting ARM64 in console" -- is satisfiable by a fact that stops being true:
CloudFormation can report UPDATE_COMPLETE with a dead fleet, and
`CompatibleArchitectures` on a layer is advisory filtering metadata, not an
enforced runtime contract (BRD 6.5). This harness is built to the opposite
standard: every point must be re-runnable and must produce the same verdict
from LIVE state, never from a cached claim or a recorded fact.

THE FIVE POINTS (BRD section 8, verbatim numbering)
-----------------------------------------------------------------------------
1. Artifact identity   -- deployed CodeSha256 == the arm64 build artifact,
                           not merely Architectures==['arm64']. When the
                           build artifact cannot be read, falls back to
                           inspecting the DEPLOYED package for wrong-arch
                           compiled objects -- which can FAIL but never PASS
                           (ENC-TSK-O96 / ENC-ISS-658).
2. Layer coherence      -- every attached layer version is arm64-compatible
                           IN FACT (inspected .so contents), not merely in
                           CompatibleArchitectures metadata.
3. Live invocation      -- the function is actually invoked and returns.
                           UPDATE_COMPLETE-with-a-dead-fleet is invisible to
                           CloudFormation (ENC-ISS-631 / DVP-ISS-103 class).
4. Integration edge     -- the component's downstream contract is exercised.
                           Function-level green is NOT system-level green.
                           Necessarily function-specific: implemented as a
                           pluggable probe registry (see PROBE_REGISTRY).
                           REPAIRED under ENC-TSK-P08/ENC-ISS-665: point 4 used
                           to read a CloudWatch log stream mid-flight -- before
                           an ERROR/Traceback had been written -- and measure
                           "freshness" against point 3's OWN invocation from
                           seconds earlier in the same run, manufacturing the
                           freshness it then accepted. Four remedies now hold
                           simultaneously: run-start freshness anchoring (never
                           use activity that postdates this run), a
                           terminated-invocation requirement (never classify an
                           invocation with no REPORT/END line; bounded poll,
                           UNKNOWN on timeout, never PASS), a structural
                           cross-point contradiction assertion (point 4 cannot
                           return PASS for a function whose point 3 FAILED in
                           this run -- this one is load-bearing and holds even
                           if the other three regress), and log-group-wide
                           evaluation (a concurrent invocation on another
                           stream can no longer be invisible). See
                           _enforce_no_pass_when_point3_failed and
                           _evaluate_schedule_window below.
5. CI predicate observed failing -- the guard covering this function exists
                           in CI and has actually been seen red, not just
                           written to look correct (ENC-ISS-556 lesson).

THE THREE-STATE CONTRACT -- READ THIS BEFORE ADDING A CHECK
-----------------------------------------------------------------------------
Every point returns exactly one of PASS / FAIL / UNKNOWN. UNKNOWN means
"this could not be checked" (permission denied, dependency unavailable, no
probe registered, no evidence found) and is NEVER collapsed into PASS. This
harness exists specifically because vacuous passes have burned this platform
twice: ENC-ISS-651's census returned 29 false clears from empty lookup lists,
and DVP-ISS-103's health probe returned HTTP 200 with checks_errored:0 while
writing nothing. A probe that cannot run must say so, loudly, at the same
severity as a probe that ran and failed. See test_verify_arm64_validation_harness.py
for the self-tests proving this (search for "unknown_not_pass").

At the function level: overall = FAIL if any point is FAIL; else, if any
point is UNKNOWN, ATTESTED when EVERY non-passing point's reason_code is in
ATTESTABLE_REASON_CODES (a narrow, explicitly named external-dependency /
ownership permission ceiling -- ENC-TSK-P09/ENC-ISS-668), otherwise plain
UNKNOWN; else PASS. Both UNKNOWN and ATTESTED are non-passing -- an
unqualified overall "pass" is structurally impossible whenever any point is
UNKNOWN, because that string is only ever produced in the branch where no
point is UNKNOWN at all. ATTESTED differs from UNKNOWN only in that it NAMES
which points could not be verified and why (see FunctionReport.attested_points
/ .attestation_note), instead of leaving a permission ceiling
indistinguishable from an undiagnosed gap. PointResult.state itself stays a
strict three-state PASS/FAIL/UNKNOWN contract -- ATTESTED exists ONLY at the
FunctionReport rollup level, never as a fourth PointResult state.

O96/ATTESTED VS ENC-ISS-665 -- READ THIS BEFORE TOUCHING EITHER REMEDIATION
-----------------------------------------------------------------------------
Two remediations in this file can look superficially similar and must never
be confused, because confusing them sanctions exactly the defect class each
one exists to prevent:

  - ENC-TSK-O96's deployed-package substitute (point 1) and ENC-TSK-P09's
    ATTESTED overall verdict (point 2's EXTERNAL_LAYER_REGISTRY) both exist
    because a check genuinely CANNOT SEE the answer: an IAM boundary that is
    not coming back, a cross-account layer this account will never be able to
    GetLayerVersion on. That is a LIMIT of the vantage point, not a wrong
    verdict -- so it is correct, and per ENC-ISS-668 necessary, to name that
    limit explicitly (ATTESTED) rather than let it sink forever into an
    undifferentiated "unknown" that 33 functions could never climb out of.
  - ENC-TSK-P08/ENC-ISS-665 is the opposite shape entirely: point 4 SAW the
    wrong answer and reported it as a pass. It read a log stream that had not
    finished writing, mid-flight, and measured "freshness" against its own
    harness run's invocation from seconds earlier. That is not a limit of
    what could be seen -- it is having looked and gotten it wrong. Applying
    an O96/ATTESTED-style relabelling to that outcome would not name a limit;
    it would sanction a false positive. So ENC-ISS-665's fix is a REPAIR
    (run-start anchoring, a termination requirement, a structural cross-point
    contradiction assertion, log-group-wide evaluation) that makes point 4
    actually correct -- never a relabelling of its wrong answer into
    something more palatable. POINT 4 IS REPAIRED, NOT RELABELLED.

Rule of thumb applied throughout this file: relabel an "unknown" only when
the check truly never got to look. Never relabel a "wrong" into anything but
FAIL. Never widen an acceptance condition to make a failing check pass.

Every PointResult also carries a `reason_code` -- a small closed vocabulary
(REASON_CODES / REASON_CODE_GLOSSARY below) distinguishing WHY a state was
reached, machine-readably, not just in the free-text `detail`. This matters
specifically because "unknown" alone conflates unrelated causes: "IAM denied
this call" (reason_code="permission_denied") and "no probe was ever written"
(reason_code="no_probe_registered") are both state=unknown but are not the
same finding -- one is a fleet/IAM fact, the other is a coverage gap.
FunctionReport.permission_denied_points (and its JSON mirror) surfaces the
former directly so a caller aggregating many functions (ENC-TSK-O89 across
26 gamma twins, ENC-TSK-O90 across Category A) can group on it without
parsing prose. The full glossary is included in every CLI JSON run under
"reason_code_glossary" so a consumer never has to read this source file to
know what a code means.

ARTIFACT TAG SCHEME -- A DIVERGENCE THIS HARNESS DOES NOT PAPER OVER
-----------------------------------------------------------------------------
Two incompatible S3 key schemes exist in this codebase today:
  - .github/workflows/_build.yml:191 writes keys as
    "{artifact_key_prefix}/{matrix.arch}-py{matrix.py_version}/{fn}-{sha}.zip"
    with matrix.py_version="3.12"/"3.11" literal strings -> DOTTED tags,
    e.g. "arm64-py3.12". This is what the build pipeline actually produces.
  - tools/verify_lambda_arch_parity.py's ARTIFACT_ARCH_TAGS (~line 437) reads
    "arm64-py312" / "x86_64-py311" -> UNDOTTED tags.
Confirmed live on 2026-08-23 under AWS_PROFILE=enceladus-agent: the object
  s3://jreese-net/lambda-artifacts/arm64-py3.12/governance_mart-<sha>.zip
exists at the DOTTED path. This harness reads the DOTTED (real, _build.yml)
layout -- see ARTIFACT_KEY_PREFIX_DEFAULT / _artifact_key() below -- and
emits a top-level "artifact_tag_scheme_divergence" warning on every run
naming both schemes, so a reader is never left to discover the mismatch
independently. tools/verify_lambda_arch_parity.py is owned by ENC-TSK-O82
and is NOT modified by this task; reconciling the two schemes is out of
scope here and is flagged, not fixed, by this file.

KNOWN PERMISSION BOUNDARIES (AWS_PROFILE=enceladus-agent, confirmed live)
-----------------------------------------------------------------------------
  - lambda:GetFunctionConfiguration, lambda:GetLayerVersion, CloudWatch Logs
    reads: ALLOWED.
  - lambda:InvokeFunction: DENIED (AccessDeniedException, confirmed
    2026-08-23 against auth-refresh). Point 3 reports UNKNOWN under this
    profile, with the reason stated explicitly -- never a fabricated pass.
  - s3:GetObject / s3:ListBucket on the lambda-artifacts bucket (jreese-net):
    DENIED, and PERMANENTLY so for agent sessions. io's policy inspection on
    2026-08-23 (ENC-ISS-659) found the denial comes from a `Deny s3:* on
    NotResource harrisonfamily-frontend` statement -- the S3 security
    boundary for every enceladus-agent-cli session, which additionally
    governs a second project's production bucket. The ENC-ISS-658 request
    for an artifact-read grant was therefore WITHDRAWN rather than pursued:
    unblocking a validation check is not a good enough reason to edit that
    statement. Point 1's primary artifact-vs-S3 comparison consequently
    reports UNKNOWN under this profile forever, and ENC-TSK-O96 added the
    deployed-package SUBSTITUTE below rather than waiting for a permission
    that is not coming. A CI OIDC role can still complete the primary check.
  - lambda:GetFunction's presigned Code.Location for the DEPLOYED package:
    ALLOWED, and NOT gated by the S3 bucket policy above (AWS-managed
    storage, same mechanism as GetLayerVersion). This is what makes point
    1's substitute path possible under the agent identity -- see
    inspect_deployed_package(). It can produce a real FAIL. It can NEVER
    produce a PASS: it establishes what is running, not that what is running
    came from the arm64 build lane, and PointResult enforces that
    structurally rather than by convention.
  - GetLayerVersion's presigned Content.Location download is NOT gated by
    the S3 bucket policy above (it is AWS-managed Lambda layer storage) --
    confirmed live by downloading enceladus-shared:12 (18124 bytes, zero
    .so files, matching the ENC-TSK-O78 census). Point 2 works fully under
    this profile.

ESTABLISHED FLEET FACTS THIS HARNESS IS DESIGNED AROUND (do not rediscover)
-----------------------------------------------------------------------------
  - enceladus-shared:10/:11/:12 are all pure-Python (zero .so at every
    version, ENC-TSK-O78 census, re-confirmed live for :12 in this task).
    v12 additionally declares CompatibleArchitectures=[x86_64, arm64].
    4 gamma functions legitimately sit on :12 while most of the fleet sits
    on :10 (ENC-ISS-656) -- point 2 must tolerate this, and does, because it
    inspects contents rather than pinning an expected version number.
  - auth-refresh and enceladus-prod-health-monitor carry NO enceladus-shared
    layer at all (ENC-TSK-O70). auth-refresh in fact carries zero
    enceladus-shared layers and one AWS-AppConfig-Extension layer (confirmed
    live). Point 2 treats "zero layers" as PASS ("vacuously coherent"), not
    FAIL and not SKIP -- it is a valid, deliberate state.

USAGE
-----------------------------------------------------------------------------
    python3 tools/verify_arm64_validation_harness.py \\
        --function-name auth-refresh-gamma \\
        --commit-sha <40-hex-sha> \\
        --profile enceladus-agent --region us-west-2

    # Multiple functions, JSON report to a file:
    python3 tools/verify_arm64_validation_harness.py \\
        --function-name auth-refresh-gamma --function-name auth-refresh \\
        --output /tmp/five-point-report.json

    # Run the harness's own self-tests (no AWS calls, proves the
    # unknown-not-pass contract):
    python3 tools/verify_arm64_validation_harness.py --self-test

Exit codes: 0 = every requested function is PASS on all 5 points.
            1 = at least one point is FAIL or UNKNOWN for some function.
            2 = usage or environment error (e.g. boto3 unavailable).

Part of ENC-PLN-086 Wave 4 / ENC-FTR-138. Does not run across the fleet --
that is ENC-TSK-O89 (26 gamma twins) and ENC-TSK-O90 (Category A), which
consume this file's JSON output as acceptance evidence.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = Path(__file__).resolve().parent

PASS = "pass"
FAIL = "fail"
UNKNOWN = "unknown"
_VALID_STATES = (PASS, FAIL, UNKNOWN)

# FunctionReport-level-only verdict (ENC-TSK-P09/ENC-ISS-668). Deliberately
# NOT added to _VALID_STATES: PointResult stays a strict three-state
# PASS/FAIL/UNKNOWN contract forever -- ATTESTED is a rollup concept that
# names WHY a set of UNKNOWN points is a documented permission ceiling, not a
# fourth thing a single point can independently be. See FunctionReport.overall
# and the "O96/ATTESTED VS ENC-ISS-665" module-docstring section above.
ATTESTED = "attested"

# The narrow, explicitly enumerated set of reason_codes that may lift a
# FunctionReport's overall verdict from plain UNKNOWN to the named ATTESTED
# state -- and ONLY when every single non-passing point on that function
# carries one of them. This is intentionally small: it is NOT "any unknown is
# fine." Widening it to cover ordinary permission_denied, no_probe_registered,
# or any other reason code would blur exactly the line the module docstring's
# "O96/ATTESTED VS ENC-ISS-665" section draws -- a documented external
# dependency/ownership ceiling on one specific, named layer is a limit of the
# vantage point; a generic "we could not check this" is not automatically the
# same thing and must not be laundered into looking like one.
ATTESTABLE_REASON_CODES = {
    "external_dependency_declared",
    "external_dependency_owned_devops",
    # ENC-TSK-P18 / ENC-ISS-668. Admitted ONLY on an exact, whole-string ARN
    # match against EXTERNAL_LAYER_ARN_ALLOWLIST. Deliberately NOT accompanied
    # by "cross_account_layer_unverifiable": that code means "this layer lives
    # in another account and nothing declares it," which is precisely the
    # un-attested case the negative control exists to keep un-attested. If a
    # future edit ever adds cross_account_layer_unverifiable to this set, the
    # allowlist stops being an allowlist -- every cross-account layer would
    # inherit the exemption, which is the vacuous pass this task was opened to
    # prevent.
    "external_dependency_cross_account_allowlisted",
    # ENC-TSK-P19 / ENC-ISS-665. A declared OWNERSHIP ceiling, resolved from
    # infrastructure/devops_lambda_ownership_snapshot.json by exact name
    # match: this plane does not own the function, so this plane's harness has
    # no standing to assert its downstream contract. Same shape as
    # external_dependency_owned_devops one layer up. The point is still
    # UNKNOWN and still never PASS -- ATTESTED names it as declared rather
    # than leaving it as undifferentiated silence.
    "not_applicable_on_plane_devops_owned",
}

# Machine-readable reason codes -- every PointResult carries one of these, not
# just a prose `detail`. This exists because "unknown" alone does not tell a
# downstream consumer (ENC-TSK-O89 aggregating 26 functions, ENC-TSK-O90
# across Category A) WHY a point could not be checked. "permission_denied"
# in particular is the operationally critical code: under
# AWS_PROFILE=enceladus-agent, points 1 (partially) and 3 are STRUCTURALLY
# blocked by IAM (lambda:InvokeFunction and s3:GetObject on jreese-net are
# both explicitly denied, confirmed live 2026-08-23) and will report
# "unknown"/"permission_denied" on every run under this identity until
# either an IAM grant lands or the harness runs from a privileged terminal /
# CI OIDC role. That is a fleet/IAM fact, not a probe defect -- a consumer
# grouping by reason_code=="permission_denied" can distinguish "this
# function is broken" from "this identity cannot see the answer" without
# re-reading prose. See REASON_CODE_GLOSSARY below for the full vocabulary,
# which is also emitted in the CLI's JSON output for self-description.
REASON_CODES = {
    "unspecified": "reason_code was not set at this call site -- treat as a gap in the harness, not a real classification",
    # point 1 -- artifact_identity
    "config_read_error": "could not read the function's configuration (transient AWS error, throttling, etc.)",
    "wrong_architecture": "deployed Architectures does not match the expected arch -- wrong build target entirely",
    "no_commit_sha": "no --commit-sha supplied; the expected S3 artifact key cannot be resolved",
    "artifact_name_unresolved": "the deployed function name has no entry in envs/<env>.yaml's function_name_map, so the artifact's source-directory basename cannot be resolved and the S3 key cannot be built (ENC-TSK-P06)",
    "artifact_missing": "the expected artifact object does not exist at the resolved S3 key",
    "permission_denied": "the calling identity is explicitly denied the AWS action needed to complete this check",
    "s3_read_error": "an S3 error occurred that is not a permission denial or a missing key",
    "digest_match": "recomputed artifact digest matches the deployed CodeSha256",
    "digest_mismatch": "recomputed artifact digest does not match the deployed CodeSha256",
    # point 1 -- DEPLOYED-PACKAGE SUBSTITUTE (ENC-TSK-O96 / ENC-ISS-658).
    # These codes are carried on PointResult.substitute, never as the point's
    # own reason_code when the point is unknown -- see check_artifact_identity.
    # NONE of them can produce PASS: this path inspects the deployed package,
    # which says nothing about whether that package came from the arm64 BUILD.
    "deployed_package_unavailable": "lambda:GetFunction returned no presigned Code.Location, or the call itself failed -- the deployed package could not be fetched for substitute inspection",
    "deployed_package_download_error": "the deployed package's presigned Code.Location could not be downloaded",
    "deployed_package_digest_unverified": "the downloaded bytes do not hash to the deployed CodeSha256 -- they cannot be trusted to BE the deployed package, so nothing inspected in them is evidence about it",
    "deployed_package_bad_zip": "the downloaded deployed package is not a valid zip archive",
    "deployed_package_arch_mismatch": "the DEPLOYED package contains compiled objects of the wrong machine type -- direct evidence the live code cannot be the arm64 build",
    "deployed_package_unclassifiable": "the deployed package contains compiled objects that could not be architecture-classified",
    "deployed_package_no_native_objects": "the deployed package contains zero compiled objects -- architecture-neutral, so it carries no contrary evidence and also no positive proof of provenance",
    "deployed_package_arch_consistent": "every compiled object in the deployed package matches the expected architecture -- no contrary evidence, but provenance against the build artifact remains unread",
    # point 2 -- layer_coherence
    "zero_layers": "the function declares no layers at all -- vacuously coherent",
    "layer_contents_verified": "every attached layer's real content was downloaded and inspected (pure-Python or arch-matched compiled objects)",
    "compiled_object_mismatch": "a layer's compiled object does not match the function's actual architecture",
    "layer_arn_unparseable": "a layer ARN could not be parsed into name/version",
    "layer_not_found": "GetLayerVersion could not find the layer version (commonly a cross-account AWS-managed layer that cannot be introspected from this account)",
    # ENC-TSK-P09 / ENC-ISS-668 -- external-dependency register. These are
    # deliberately DISTINCT from layer_not_found: that code means "we could
    # not find out why," these two mean "we know exactly why, and who owns
    # it." Both remain UNKNOWN state -- neither is ever promoted to PASS --
    # but they are the specific, narrow set FunctionReport.overall may lift
    # to the named ATTESTED verdict (see ATTESTABLE_REASON_CODES).
    "external_dependency_declared": "the layer is a documented external (commonly cross-account) dependency whose architecture is recorded as a declared fact in EXTERNAL_LAYER_REGISTRY, not independently verified by downloading and inspecting its content -- still unknown, never promoted to pass, but distinguishable from a genuine layer_not_found mystery",
    "external_dependency_owned_devops": "the layer is owned by a separate repo/team (NX-2021-L/devops), recorded in EXTERNAL_LAYER_REGISTRY so it is never folded into a generic layer_not_found -- still unknown, never promoted to pass",
    # ENC-TSK-P18 / ENC-ISS-668 -- cross-account ceiling, split into the two
    # cases that must NOT share a bucket. Both are UNKNOWN; only the first is
    # attestable. Splitting them is the whole point: "another account owns
    # this and we have declared which one" is a legible ceiling, while
    # "another account owns this and nothing declares it" is still an open
    # question, and neither is the same thing as "GetLayerVersion returned
    # ResourceNotFound and we do not know why" (layer_not_found).
    "external_dependency_cross_account_allowlisted": "the layer ARN matched EXACTLY (whole-string, never by prefix or wildcard) an entry in EXTERNAL_LAYER_ARN_ALLOWLIST, which records its architecture as a DECLARED fact sourced from infrastructure/component_dependency_closure.json -- a documented cross-account permission ceiling, still unknown and never promoted to pass, but attestable",
    "cross_account_layer_unverifiable": "the layer is owned by a DIFFERENT AWS account than the function that attaches it, and no exact-ARN entry in EXTERNAL_LAYER_ARN_ALLOWLIST declares it -- a real cross-account ceiling (so: not a plain layer_not_found mystery) but an UNDECLARED one, so it is deliberately NOT attestable and sinks the function to plain unknown",
    "layer_download_error": "the layer's presigned content URL could not be downloaded",
    "layer_content_unclassifiable": "the layer contains compiled objects that could not be architecture-classified",
    "bad_layer_zip": "the downloaded layer content is not a valid zip archive",
    # point 3 -- live_invocation
    "function_not_found": "the target function does not exist",
    "invoke_error": "the invoke call failed for a reason other than permission or a missing function",
    "response_unreadable": "the invoke call returned but the response payload could not be read",
    "function_error": "the function was invoked and returned a FunctionError",
    "invoked_ok": "the function was invoked and returned without a FunctionError",
    # point 4 -- integration_edge
    "no_probe_registered": "no per-function integration probe is registered -- function-level state says nothing about the downstream contract",
    # ENC-TSK-P19 / ENC-ISS-665 -- declared ownership, not a skip.
    "not_applicable_on_plane_devops_owned": "the function is declared, by EXACT name match, in infrastructure/devops_lambda_ownership_snapshot.json's functions[] -- it is owned by NX-2021-L/devops, so enceladus deploy validation has no standing to assert its downstream contract. NOT_APPLICABLE_ON_PLANE: the gate still fires and still records an answer; it is simply a declared answer rather than a probed one. Never a silent skip and never a pass",
    "devops_ownership_declaration_unreadable": "the devops ownership declaration (infrastructure/devops_lambda_ownership_snapshot.json) could not be read or parsed, so NO function can be resolved to NOT_APPLICABLE_ON_PLANE this run -- a missing declaration is an unknown, never a silent pass and never an assumed non-devops classification (ENC-TSK-P15 AC-3/AC-5 discipline, reused)",
    "probe_contract_mismatch": "the probe registered for this function asserts a downstream the function does not reference in its own configuration -- refused rather than run, because judging a function on an artifact another function writes produces a PASS attributable to the wrong component (ENC-ISS-678). UNKNOWN, never pass and never fail: the edge is not established broken, it is not established at all",
    "probe_contract_unverifiable": "the probe declares a downstream env key but the function's configuration could not be read to confirm it references that downstream -- fail-safe to unknown rather than run a probe whose attribution cannot be checked (ENC-ISS-678)",
    "probe_error": "the registered probe raised an exception",
    "probe_invalid_state": "the registered probe returned a state outside pass/fail/unknown",
    "probe_result": "the registered probe ran to completion and returned this state",
    "point3_point4_contradiction": "point 4's probe reported pass while point 3 (live_invocation) FAILED in this same run -- structurally overridden to fail (ENC-TSK-P08/ENC-ISS-665 remedy 3, load-bearing); a function that just failed live invocation cannot simultaneously have a healthy downstream integration edge, and this override is independent of the freshness/anchoring logic",
    # point 5 -- ci_predicate_observed_failing
    "negative_control_missing": "no negative-control test file exists for the guard covering this function",
    "negative_control_check_error": "the negative-control test could not be run locally",
    "negative_control_failing": "the negative-control test does not currently demonstrate the guard can fail",
    "gh_unavailable": "the gh CLI is not available -- cannot query real CI history",
    "gh_query_error": "gh run list failed",
    "gh_output_unparseable": "gh run list returned output that could not be parsed as JSON",
    "no_ci_history_found": "no failed runs of the guard's workflow were found within the lookback window",
    "ci_history_confirmed_red": "a real, historical CI run shows the specific guard step failing",
    "ci_history_inconclusive": "failed workflow runs exist in the lookback window, but none show this guard step failing",
}
REASON_CODE_GLOSSARY = REASON_CODES  # exported name used in CLI JSON output

ARTIFACT_BUCKET_DEFAULT = "jreese-net"
ARTIFACT_KEY_PREFIX_DEFAULT = "lambda-artifacts"

DEFAULT_REPO = "NX-2021-L/enceladus"
DEFAULT_CI_WORKFLOW = "ci.yml"
DEFAULT_CI_STEP = "Verify Lambda architecture parity"
DEFAULT_NEGATIVE_CONTROL_TEST = "tools/test_verify_lambda_arch_parity.py"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _err(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"


def _load_classify_so() -> Callable[[Path], Optional[str]]:
    """Reuse the ELF-classification logic from verify_lambda_package_arch.py
    instead of duplicating it. That file is not in ENC-TSK-O88's exclusion
    list (only 02-compute.yaml, lambda_workflow_manifest.json,
    verify_lambda_arch_parity.py and _build.yml are) and is imported
    read-only here -- never modified.
    """
    mod_name = "_verify_lambda_package_arch_borrowed"
    spec = importlib.util.spec_from_file_location(
        mod_name, TOOLS_DIR / "verify_lambda_package_arch.py",
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    # Register in sys.modules before exec: the target module defines dataclasses,
    # and dataclass's type-hint resolution looks the module up by name in
    # sys.modules -- without this it raises AttributeError on a None lookup.
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod.classify_so  # type: ignore[no-any-return]


def _default_downloader(url: str) -> bytes:
    """Fetch a presigned URL's bytes. Falls back to certifi's CA bundle on
    CERTIFICATE_VERIFY_FAILED: some Python.org macOS builds ship without a
    usable system trust store, which otherwise surfaces as an SSL error on
    every download -- indistinguishable at a glance from an access problem.
    Confirmed live in this environment (enceladus-shared:12 download).
    """
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310 - trusted AWS-signed URL
            return resp.read()
    except urllib.error.URLError as exc:
        if "CERTIFICATE_VERIFY_FAILED" not in str(exc):
            raise
        import certifi
        import ssl

        ctx = ssl.create_default_context(cafile=certifi.where())
        with urllib.request.urlopen(url, timeout=30, context=ctx) as resp:  # noqa: S310
            return resp.read()


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

@dataclass
class PointResult:
    point: int
    name: str
    state: str
    detail: str
    reason_code: str = "unspecified"
    checked_at: str = field(default_factory=_now)
    # Populated only by point 1, only when the primary (S3 build-artifact)
    # check could not complete. Carries its OWN state/reason_code/detail for
    # the substitute deployed-package inspection, kept separate from the
    # point's own reason_code on purpose: ENC-TSK-O89 and ENC-TSK-O90
    # aggregate on FunctionReport.permission_denied_points, and overwriting
    # the point's reason_code with a substitute code would silently delete
    # the IAM fact those consumers group by. See check_artifact_identity.
    substitute: Optional[dict] = None

    def __post_init__(self) -> None:
        if self.state not in _VALID_STATES:
            raise ValueError(f"invalid state {self.state!r}; must be one of {_VALID_STATES}")
        if self.reason_code not in REASON_CODES:
            raise ValueError(f"invalid reason_code {self.reason_code!r}; must be one of {sorted(REASON_CODES)}")
        if self.substitute is not None:
            sub_state = self.substitute.get("state")
            sub_reason = self.substitute.get("reason_code")
            if sub_state not in _VALID_STATES:
                raise ValueError(f"invalid substitute state {sub_state!r}; must be one of {_VALID_STATES}")
            if sub_state == PASS:
                raise ValueError(
                    "a substitute check may never report PASS -- it is weaker evidence than the "
                    "check it stands in for, and promoting it would reproduce the vacuous-pass "
                    "defect this harness exists to eliminate (see ENC-ISS-658)")
            if sub_reason not in REASON_CODES:
                raise ValueError(f"invalid substitute reason_code {sub_reason!r}; must be one of {sorted(REASON_CODES)}")

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FunctionReport:
    function_name: str
    points: List[PointResult]
    warnings: List[str] = field(default_factory=list)
    generated_at: str = field(default_factory=_now)

    @property
    def overall(self) -> str:
        """FAIL beats everything. Otherwise, UNKNOWN sinks the verdict --
        UNLESS every single non-passing point's reason_code is in
        ATTESTABLE_REASON_CODES (ENC-TSK-P09/ENC-ISS-668), in which case the
        verdict is the explicitly-named ATTESTED rather than an
        undifferentiated UNKNOWN. Structural guarantee: this can NEVER return
        PASS when UNKNOWN is present in `states` -- that string literal is
        only ever produced by the final `return PASS`, which is unreachable
        from inside the `if UNKNOWN in states` branch. See the module
        docstring's "O96/ATTESTED VS ENC-ISS-665" section before touching
        ATTESTABLE_REASON_CODES: it must stay narrow, never widened to make a
        non-passing function read as fine.
        """
        states = {p.state for p in self.points}
        if FAIL in states:
            return FAIL
        if UNKNOWN in states:
            non_pass = [p for p in self.points if p.state != PASS]
            if non_pass and all(p.reason_code in ATTESTABLE_REASON_CODES for p in non_pass):
                return ATTESTED
            return UNKNOWN
        return PASS

    @property
    def permission_denied_points(self) -> List[int]:
        """Points blocked specifically by an IAM/access denial, as opposed to
        any other reason a point might be unknown (no probe, no CI evidence,
        transient error, ...). This is the exact aggregation ENC-PLN-086 Wave
        4 needs: 'unknown because this identity cannot see the answer' is a
        fleet/IAM fact, not a per-function defect, and must be distinguishable
        from every other kind of unknown without a human reading `detail`.
        """
        return [p.point for p in self.points if p.reason_code == "permission_denied"]

    @property
    def attested_points(self) -> List[int]:
        """Points that are UNKNOWN specifically because of a documented
        external-dependency/ownership permission ceiling (ENC-TSK-P09/
        ENC-ISS-668) -- exactly the points an ATTESTED overall verdict is
        naming. Empty whenever overall != ATTESTED: a function with even one
        OTHER, non-attestable unknown does not get to claim any of its
        unknowns are "just" a documented ceiling -- the overall verdict for
        that function is plain UNKNOWN, and this list reflects that.
        """
        if self.overall != ATTESTED:
            return []
        return [p.point for p in self.points
                if p.state == UNKNOWN and p.reason_code in ATTESTABLE_REASON_CODES]

    @property
    def attestation_note(self) -> Optional[str]:
        """None unless overall == ATTESTED, in which case this NAMES the
        unverified points and why -- the concrete text of "a permission
        ceiling is not a defect" (ENC-ISS-668): every other point passed, and
        these specific points are unknown for a specific, documented,
        non-fabricated reason, not silence.
        """
        if self.overall != ATTESTED:
            return None
        named = "; ".join(
            f"point {p.point} ({p.name}): {p.reason_code}"
            for p in self.points if p.point in self.attested_points
        )
        return (
            f"ATTESTED, not PASS: every other point on {self.function_name!r} is pass; the "
            f"following are unknown solely because of a documented external-dependency/ownership "
            f"permission ceiling, never a fabricated pass -- {named}"
        )

    def to_dict(self) -> dict:
        return {
            "function_name": self.function_name,
            "overall": self.overall,
            "generated_at": self.generated_at,
            "points": [p.to_dict() for p in self.points],
            "permission_denied_points": self.permission_denied_points,
            "attested_points": self.attested_points,
            "attestation_note": self.attestation_note,
            "warnings": self.warnings,
        }


# ---------------------------------------------------------------------------
# Point 1 -- artifact identity
# ---------------------------------------------------------------------------

def _classify_so_tree(root: Path, expected_arch: str,
                       classify_so: Callable[[Path], Optional[str]]) -> Tuple[List[str], List[str], int]:
    """Classify every compiled object under `root`.

    Returns (mismatches, unclassifiable, total_so_count). Shared by point 2
    (layer contents) and point 1's deployed-package substitute so the two
    cannot drift apart on what counts as a compiled object or as a mismatch.
    """
    so_files = list(root.rglob("*.so")) + list(root.rglob("*.so.*"))
    mismatches: List[str] = []
    unknowns: List[str] = []
    for so in so_files:
        arch = classify_so(so)
        if arch is None:
            unknowns.append(so.name)
        elif arch != expected_arch:
            mismatches.append(f"{so.name}={arch}")
    return mismatches, unknowns, len(so_files)


def inspect_deployed_package(
    lambda_client, function_name: str, expected_arch: str,
    downloader: Callable[[str], bytes] = _default_downloader,
    classify_so: Optional[Callable[[Path], Optional[str]]] = None,
) -> Tuple[str, str, str]:
    """SUBSTITUTE evidence for point 1 when the S3 build artifact cannot be read.

    WHY THIS EXISTS (ENC-TSK-O96, remediating ENC-ISS-658)
    ---------------------------------------------------------------------
    Point 1's primary check re-reads the arm64 BUILD artifact out of
    s3://jreese-net/lambda-artifacts/ and compares its digest to the deployed
    CodeSha256. Under AWS_PROFILE=enceladus-agent that read is denied, and the
    grant was WITHDRAWN rather than pursued: io's policy inspection on
    2026-08-23 found the denial comes from a `Deny s3:* on NotResource
    harrisonfamily-frontend` statement that is the S3 security boundary for
    every agent session and additionally governs a second project's production
    bucket (ENC-ISS-659). Editing that to make a validation check convenient is
    the wrong trade. So the permission is not coming, and point 1 needed
    another way to say something true.

    `lambda:GetFunction` returns a presigned `Code.Location` for the DEPLOYED
    package which downloads WITHOUT any bucket permission -- the same
    AWS-managed mechanism that already makes point 2 work fully under this
    identity. Inspecting that package's own compiled objects gives DIRECT
    evidence about the property point 1 exists to protect, and can return a
    real FAIL with no IAM change at all.

    WHAT IT DELIBERATELY CANNOT DO -- READ BEFORE PROMOTING ANY BRANCH
    ---------------------------------------------------------------------
    This function NEVER returns PASS, and PointResult.__post_init__ enforces
    that structurally. Inspecting the deployed package tells you what is
    running; it does not tell you that what is running came from the arm64
    build lane. A pure-Python function has zero compiled objects, so a
    consistent result there is indistinguishable from a package built from the
    wrong commit entirely. Promoting that to PASS would be exactly the vacuous
    pass this harness was built to eliminate -- ENC-ISS-651's census returned
    29 false clears from empty lookup lists, and DVP-ISS-103's probe returned
    HTTP 200 with checks_errored:0 while writing nothing. An absence of
    contrary evidence is not evidence of provenance.

    Returns (state, reason_code, note); state is FAIL or UNKNOWN only.
    """
    if classify_so is None:
        classify_so = _load_classify_so()

    try:
        fn = lambda_client.get_function(FunctionName=function_name)
    except Exception as exc:  # noqa: BLE001 - any failure means "no substitute evidence"
        return UNKNOWN, "deployed_package_unavailable", (
            f"lambda:GetFunction failed, no substitute inspection possible: {_err(exc)}")

    code = fn.get("Code") or {}
    url = code.get("Location")
    if not url:
        return UNKNOWN, "deployed_package_unavailable", (
            "lambda:GetFunction returned no Code.Location presigned URL")

    deployed_sha = ((fn.get("Configuration") or {}).get("CodeSha256")) or ""

    try:
        raw = downloader(url)
    except Exception as exc:  # noqa: BLE001
        return UNKNOWN, "deployed_package_download_error", (
            f"could not download the deployed package: {_err(exc)}")

    # Verify the bytes we are about to inspect really ARE the deployed package.
    # Without this the whole substitute is an inspection of an unattributed
    # blob -- and a check whose subject is unproven is not evidence.
    digest = base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii")
    if not deployed_sha or digest != deployed_sha:
        return UNKNOWN, "deployed_package_digest_unverified", (
            f"downloaded bytes hash to {digest} but the function reports CodeSha256 "
            f"{deployed_sha or '<absent>'} -- cannot confirm these bytes are the deployed "
            f"package, so nothing found in them is evidence about it")

    try:
        with tempfile.TemporaryDirectory(prefix="verify_arm64_pkg_") as tmp:
            tmp_path = Path(tmp)
            zpath = tmp_path / "package.zip"
            zpath.write_bytes(raw)
            with zipfile.ZipFile(zpath) as zf:
                zf.extractall(tmp_path / "content")
            mismatches, unknowns, total = _classify_so_tree(
                tmp_path / "content", expected_arch, classify_so)
    except zipfile.BadZipFile as exc:
        return UNKNOWN, "deployed_package_bad_zip", (
            f"the downloaded deployed package is not a valid zip: {exc}")

    provenance_caveat = (
        "provenance against the arm64 build artifact remains UNREAD (s3:GetObject withdrawn "
        "per ENC-ISS-658/ENC-ISS-659) -- this is not a point 1 pass")

    if mismatches:
        return FAIL, "deployed_package_arch_mismatch", (
            f"the DEPLOYED package (CodeSha256 {deployed_sha}, verified) contains "
            f"{len(mismatches)} compiled object(s) that are not {expected_arch!r}: "
            f"{', '.join(mismatches[:5])} -- direct evidence the live code cannot be the "
            f"{expected_arch} build, established without reading S3 at all")
    if unknowns:
        return UNKNOWN, "deployed_package_unclassifiable", (
            f"the deployed package contains {len(unknowns)} compiled object(s) that could not "
            f"be classified: {', '.join(unknowns[:5])}; {provenance_caveat}")
    if total == 0:
        return UNKNOWN, "deployed_package_no_native_objects", (
            f"the deployed package (CodeSha256 {deployed_sha}, verified) contains zero compiled "
            f"objects, so it is architecture-neutral and CANNOT carry contrary evidence -- a "
            f"package built from the wrong commit entirely would look identical here; "
            f"{provenance_caveat}")
    return UNKNOWN, "deployed_package_arch_consistent", (
        f"all {total} compiled object(s) in the deployed package (CodeSha256 {deployed_sha}, "
        f"verified) match {expected_arch!r} -- no contrary evidence; {provenance_caveat}")


def resolve_artifact_basename(function_name: str, env: str = "v4-gamma") -> Optional[str]:
    """DEPLOYED function name -> the basename _build.yml actually writes.

    ENC-TSK-P06. Point 1 built its S3 key from the DEPLOYED function name, but
    .github/workflows/_build.yml names artifacts after the SOURCE DIRECTORY:

        deployed  auth-refresh-gamma
        artifact  lambda-artifacts/arm64-py3.12/auth_refresh-<sha>.zip

    Hyphens vs underscores, plus the environment suffix, plus names that do not
    correspond at all (devops-governance-mart-gamma <- governance_mart). So the
    key was wrong for essentially every function, and point 1 could NEVER have
    passed -- with or without the s3:GetObject grant.

    Nobody could see it. Before the ENC-ISS-659 grant landed, point 1 returned
    permission_denied and never reached the comparison, so the check's own
    defect was hidden by the check being unable to run. It surfaced the instant
    the permission existed, as a false artifact_missing FAIL.

    A heuristic would be wrong: stripping the suffix and swapping punctuation
    yields devops_governance_mart, not governance_mart. envs/<env>.yaml's
    function_name_map is the authoritative source and already exists, so this
    inverts it. Returns None when the function is unmapped, and the caller must
    then report UNKNOWN rather than a FAIL -- an unresolvable name is something
    we could not check, never evidence that the artifact is absent.
    """
    try:
        import yaml  # noqa: PLC0415 - only needed on the live path
    except ImportError:
        return None
    manifest = REPO_ROOT / "envs" / f"{env}.yaml"
    if not manifest.is_file():
        return None
    try:
        data = yaml.safe_load(manifest.read_text()) or {}
    except Exception:  # noqa: BLE001 - a malformed env file must not crash the harness
        return None
    for source_dir, deployed in (data.get("function_name_map") or {}).items():
        # one source dir can fan out to several deployed functions
        for name in str(deployed).split(","):
            if name.strip() == function_name:
                return source_dir
    return None


def _artifact_key(artifact_basename: str, expected_arch: str, py_version: str, commit_sha: str,
                   key_prefix: str = ARTIFACT_KEY_PREFIX_DEFAULT) -> str:
    # DOTTED scheme -- see module docstring "ARTIFACT TAG SCHEME".
    # artifact_basename is the SOURCE DIRECTORY name, not the deployed function
    # name -- see resolve_artifact_basename().
    return f"{key_prefix}/{expected_arch}-py{py_version}/{artifact_basename}-{commit_sha}.zip"


def _with_substitute(
    primary: PointResult, lambda_client, function_name: str, expected_arch: str,
    downloader: Callable[[str], bytes], classify_so: Optional[Callable[[Path], Optional[str]]],
) -> PointResult:
    """Attach deployed-package substitute evidence to a non-conclusive point 1.

    THE MERGE RULE, and why it is not simply "replace the verdict":

      - Substitute says FAIL -> the POINT becomes FAIL. Direct evidence that
        the deployed package is the wrong architecture is conclusive on its
        own; it needs no S3 read to be true.
      - Substitute says UNKNOWN -> the point's own state AND reason_code are
        left EXACTLY as they were. This is deliberate. ENC-TSK-O89 (26 gamma
        twins) and ENC-TSK-O90 (Category A) aggregate on
        FunctionReport.permission_denied_points, which groups on
        reason_code == "permission_denied". Overwriting that with a substitute
        code would silently erase the IAM fact those consumers exist to count
        -- turning "this identity cannot see the answer" into what looks like
        a per-function probe gap. The substitute verdict rides alongside, in
        its own field, machine-readable and separately grouped.
    """
    sub_state, sub_reason, sub_note = inspect_deployed_package(
        lambda_client, function_name, expected_arch, downloader, classify_so)
    substitute = {"check": "deployed_package_inspection", "state": sub_state,
                  "reason_code": sub_reason, "detail": sub_note}

    if sub_state == FAIL:
        return PointResult(1, "artifact_identity", FAIL,
                            f"{primary.detail} || SUBSTITUTE FOUND A REAL FAILURE: {sub_note}",
                            reason_code=sub_reason, substitute=substitute)
    return PointResult(1, "artifact_identity", primary.state,
                        f"{primary.detail} || substitute (deployed-package inspection, "
                        f"non-passing by construction): {sub_note}",
                        reason_code=primary.reason_code, substitute=substitute)


def check_artifact_identity(
    lambda_client, s3_client, function_name: str, expected_arch: str, py_version: str,
    commit_sha: Optional[str], bucket: str = ARTIFACT_BUCKET_DEFAULT,
    key_prefix: str = ARTIFACT_KEY_PREFIX_DEFAULT, *,
    env: str = "v4-gamma",
    artifact_basename: Optional[str] = None,
    downloader: Callable[[str], bytes] = _default_downloader,
    classify_so: Optional[Callable[[Path], Optional[str]]] = None,
) -> PointResult:
    """Point 1 -- artifact identity.

    PRIMARY path: recompute the digest of the arm64 build artifact in S3 and
    compare it to the deployed CodeSha256. This is the only path that can
    produce PASS, because it is the only one that reads the build artifact.

    SUBSTITUTE path (ENC-TSK-O96 / ENC-ISS-658): when the primary path cannot
    complete -- s3:GetObject denied (the grant was withdrawn, see
    inspect_deployed_package), no --commit-sha supplied, or a transient S3
    error -- inspect the DEPLOYED package instead, fetched via GetFunction's
    presigned URL which needs no bucket permission. It can turn a blind
    unknown into a real FAIL. It can never turn one into a PASS.
    """
    try:
        cfg = lambda_client.get_function_configuration(FunctionName=function_name)
    except Exception as exc:  # noqa: BLE001 - any client failure is "could not check"
        return PointResult(1, "artifact_identity", UNKNOWN,
                            f"could not read function configuration: {_err(exc)}",
                            reason_code="config_read_error")

    actual_arch = (cfg.get("Architectures") or ["unknown"])[0]
    actual_sha = cfg.get("CodeSha256", "")

    if actual_arch != expected_arch:
        return PointResult(1, "artifact_identity", FAIL,
                            f"deployed Architectures={actual_arch!r}, expected {expected_arch!r} "
                            f"-- this is not even the right build target, regardless of CodeSha256",
                            reason_code="wrong_architecture")

    if not commit_sha:
        return _with_substitute(
            PointResult(1, "artifact_identity", UNKNOWN,
                        "no --commit-sha supplied; cannot resolve the expected S3 artifact key "
                        "without knowing which commit was meant to be deployed",
                        reason_code="no_commit_sha"),
            lambda_client, function_name, expected_arch, downloader, classify_so)

    # An explicit basename wins over the map: a caller that already knows which
    # source directory built this function should not need envs/ on disk.
    basename = artifact_basename or resolve_artifact_basename(function_name, env)
    if basename is None:
        return _with_substitute(
            PointResult(1, "artifact_identity", UNKNOWN,
                        f"{function_name!r} has no function_name_map entry in envs/{env}.yaml, so "
                        f"the artifact's source-directory basename cannot be resolved. Reporting "
                        f"UNKNOWN rather than a missing-artifact FAIL: an unresolvable name is "
                        f"something we could not check, not evidence the artifact is absent.",
                        reason_code="artifact_name_unresolved"),
            lambda_client, function_name, expected_arch, downloader, classify_so)

    key = _artifact_key(basename, expected_arch, py_version, commit_sha, key_prefix)
    try:
        obj = s3_client.get_object(Bucket=bucket, Key=key)
        body = obj["Body"].read()
    except Exception as exc:  # noqa: BLE001
        msg = _err(exc)
        if "NoSuchKey" in msg or "404" in msg:
            return PointResult(1, "artifact_identity", FAIL,
                                f"expected artifact s3://{bucket}/{key} does not exist -- "
                                f"the deployed code cannot be this build",
                                reason_code="artifact_missing")
        if "AccessDenied" in msg or "Forbidden" in msg or "403" in msg:
            return _with_substitute(
                PointResult(1, "artifact_identity", UNKNOWN,
                            f"S3 GetObject denied for s3://{bucket}/{key} under the calling identity "
                            f"(enceladus-agent-cli is denied s3 on this bucket by the NotResource Deny "
                            f"documented in ENC-ISS-659; the grant was WITHDRAWN rather than pursued, so "
                            f"this denial is PERMANENT for agent sessions) -- only a broader-scoped read "
                            f"role (e.g. the CI OIDC role) can complete the primary check",
                            reason_code="permission_denied"),
                lambda_client, function_name, expected_arch, downloader, classify_so)
        return _with_substitute(
            PointResult(1, "artifact_identity", UNKNOWN, f"S3 read error for {key}: {msg}",
                        reason_code="s3_read_error"),
            lambda_client, function_name, expected_arch, downloader, classify_so)

    digest = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
    if digest == actual_sha:
        return PointResult(1, "artifact_identity", PASS,
                            f"deployed CodeSha256 {actual_sha} matches recomputed digest of s3://{bucket}/{key}",
                            reason_code="digest_match")
    return PointResult(1, "artifact_identity", FAIL,
                        f"deployed CodeSha256 {actual_sha} != recomputed {digest} for s3://{bucket}/{key} "
                        f"-- live code diverges from the expected arm64 artifact",
                        reason_code="digest_mismatch")


# ---------------------------------------------------------------------------
# Point 2 -- layer coherence
# ---------------------------------------------------------------------------

# External-dependency register (ENC-TSK-P09 / ENC-ISS-668).
#
# 33 of 51 gamma functions attach AWS-AppConfig-Extension-Arm64:147, owned by
# AWS account 359756378197. GetLayerVersion cannot reach another account's
# layer version from this account -- confirmed live 2026-08-23 -- so those 33
# functions were stuck reporting layer_not_found on point 2 forever, which
# sank their FunctionReport.overall to plain UNKNOWN with no way to ever reach
# any other verdict. This register records the specific, DECLARED facts this
# harness already knows about specific named external dependencies, so point 2
# can classify them distinctly from a genuine "we don't know why" mystery --
# without ever pretending to have inspected bytes it cannot reach. Consulted
# ONLY as a fallback, after a real GetLayerVersion attempt fails; a future IAM
# or account change that makes the real check possible again is never shadowed
# by this table (see _inspect_one_layer).
#
# Keyed by LAYER NAME (not ARN, not version) -- the facts recorded here are
# properties of the named artifact/family, not of one specific version.
EXTERNAL_LAYER_REGISTRY: Dict[str, dict] = {
    # AWS publishes this Lambda extension under architecture-specific NAMES
    # (this one, and a plain "AWS-AppConfig-Extension" for x86_64) -- the
    # "-Arm64" suffix IS the vendor's own architecture declaration for this
    # artifact family. That is recorded here as a declared fact, once, rather
    # than parsed from the ARN string on every run (a heuristic on top of a
    # heuristic is exactly the class of mistake ENC-TSK-P06 already burned
    # this file on once). Version :147 confirmed live 2026-08-23.
    "AWS-AppConfig-Extension-Arm64": {
        "declared_arch": "arm64",
        "owner_account": "359756378197",
        "classification": "aws_managed_cross_account",
        "reason_code": "external_dependency_declared",
        "note": (
            "AWS-managed cross-account layer (owner account 359756378197, confirmed live "
            "2026-08-23 for version 147). lambda:GetLayerVersion cannot reach another "
            "account's layer version from this account -- this is a permission ceiling, not "
            "a probe defect. Declared arch 'arm64' comes from the layer's own AWS-assigned "
            "name (the '-Arm64' suffix distinguishes this extension's architecture-specific "
            "variants), not from CompatibleArchitectures metadata and not from content this "
            "harness has inspected."
        ),
    },
    # Owned by NX-2021-L/devops -- a DIFFERENT repo/team, not an AWS-managed
    # layer and not this harness's own build lane. Per ENC-TSK-P09 these must
    # be classified DISTINCTLY from layer_not_found: folding a known-owned,
    # known-reason dependency into the same bucket as a genuine mystery would
    # hide who owns the remediation and why the check cannot see it. Versions
    # :3 (pyarrow) and :2 (numpy) confirmed live 2026-08-23.
    "devops-json-to-parquet-pyarrow": {
        "declared_arch": None,
        "owner_account": None,
        "classification": "devops_owned",
        "reason_code": "external_dependency_owned_devops",
        "note": (
            "Owned by NX-2021-L/devops (a separate repo/team from this harness's own build "
            "lane), not an AWS-managed layer and not a resolution failure. Architecture is "
            "not independently declared here; this only records OWNERSHIP so the point is "
            "never miscategorized as layer_not_found."
        ),
    },
    "devops-json-to-parquet-numpy": {
        "declared_arch": None,
        "owner_account": None,
        "classification": "devops_owned",
        "reason_code": "external_dependency_owned_devops",
        "note": (
            "Owned by NX-2021-L/devops (a separate repo/team from this harness's own build "
            "lane), not an AWS-managed layer and not a resolution failure. Architecture is "
            "not independently declared here; this only records OWNERSHIP so the point is "
            "never miscategorized as layer_not_found."
        ),
    },
}


# ---------------------------------------------------------------------------
# ENC-TSK-P18 / ENC-ISS-668 -- EXACT-MATCH cross-account layer ARN allowlist.
#
# WHY A SECOND TABLE, NEXT TO EXTERNAL_LAYER_REGISTRY, RATHER THAN A WIDER
# ONE: EXTERNAL_LAYER_REGISTRY above is keyed by layer NAME, because the facts
# it records (who owns this artifact family, what the vendor's own naming
# convention declares about its architecture) are properties of the family.
# That is the right key for what it does and it is left exactly as ENC-TSK-P09
# built it. It is the WRONG key for an exemption that lifts a function's
# verdict, because a name key admits every version and every account that ever
# publishes that name. This table is keyed by the COMPLETE ARN -- region,
# account, name AND version -- and is matched with `==` on the whole string.
# No prefix. No wildcard. No normalization, no case-folding, no
# version-stripping: `arn:...:147` does not admit `arn:...:1470`, and
# `arn:...:147:anything` is simply a different string that is not in the dict.
#
# SOURCE OF TRUTH: infrastructure/component_dependency_closure.json, the
# governed closure ENC-TSK-P11 landed one commit ago, which already declares
# this dependency with its architecture:
#
#     {"id": "appconfig-extension-arm64", "kind": "external_layer",
#      "declared_architecture": "arm64",
#      "layer_arn": "arn:aws:lambda:us-west-2:359756378197:layer:AWS-AppConfig-Extension-Arm64:147"}
#
# Reading it there rather than re-typing it here is the same "reused, not
# reinvented" discipline ENC-TSK-P15's ownership snapshot established: a
# second hand-maintained copy of a governed fact is a second thing that can
# drift, and a drifted exemption table is an exemption nobody reviewed.
#
# FAIL-CLOSED: if the closure cannot be read or parsed, this returns an EMPTY
# allowlist. Every cross-account layer then resolves to the NON-attestable
# cross_account_layer_unverifiable and every affected function sinks to plain
# UNKNOWN. The failure direction is deliberate -- an unreadable declaration
# must never widen what is exempt.
# ---------------------------------------------------------------------------

COMPONENT_CLOSURE_PATH = REPO_ROOT / "infrastructure" / "component_dependency_closure.json"

# A COMPLETE layer version ARN and nothing less. An allowlist key that does not
# match this is rejected at load time rather than stored: a key like
# "arn:aws:lambda:us-west-2:359756378197:layer:AWS-AppConfig-Extension-Arm64"
# (no version) or one ending in "*" is an attempt -- accidental or not -- to
# express a prefix/wildcard exemption in a table whose entire contract is that
# it has none.
_FULL_LAYER_VERSION_ARN_RE = re.compile(
    r"^arn:aws:lambda:[a-z0-9-]+:(\d{12}):layer:[A-Za-z0-9_-]+:(\d+)$")

_ALLOWLIST_CACHE: Dict[str, Dict[str, dict]] = {}


def _layer_arn_account(layer_arn: str) -> Optional[str]:
    """The 12-digit owner account from a complete layer version ARN, or None if
    the ARN is not one. Used to tell a cross-account ceiling apart from a
    same-account failure -- never used to grant an exemption."""
    m = _FULL_LAYER_VERSION_ARN_RE.match(layer_arn or "")
    return m.group(1) if m else None


def load_external_layer_arn_allowlist(
    path: Optional[Path] = None, *, use_cache: bool = True,
) -> Dict[str, dict]:
    """Build the exact-ARN allowlist from the governed component closure.

    Every dependency with kind == "external_layer" that carries a complete
    layer_arn contributes exactly ONE key: that ARN, verbatim. Entries whose
    ARN is not a complete layer version ARN are skipped, not coerced.
    """
    key = str(path or COMPONENT_CLOSURE_PATH)
    if use_cache and key in _ALLOWLIST_CACHE:
        return _ALLOWLIST_CACHE[key]

    allowlist: Dict[str, dict] = {}
    try:
        raw = json.loads(Path(key).read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - fail closed: no closure => no exemptions
        if use_cache:
            _ALLOWLIST_CACHE[key] = allowlist
        return allowlist

    for component in raw.get("components", []) or []:
        if not isinstance(component, dict):
            continue
        for dep in component.get("dependencies", []) or []:
            if not isinstance(dep, dict) or dep.get("kind") != "external_layer":
                continue
            arn = dep.get("layer_arn")
            if not isinstance(arn, str) or not _FULL_LAYER_VERSION_ARN_RE.match(arn):
                # Not a complete ARN -> not admissible as an exact-match key.
                continue
            allowlist[arn] = {
                "declared_arch": dep.get("declared_architecture"),
                "owner_account": _layer_arn_account(arn),
                "dependency_id": dep.get("id"),
                "component": component.get("name"),
                "owning_repository": dep.get("owning_repository"),
                "source": "infrastructure/component_dependency_closure.json",
            }
    if use_cache:
        _ALLOWLIST_CACHE[key] = allowlist
    return allowlist


def lookup_allowlisted_layer_arn(
    layer_arn: str, allowlist: Optional[Dict[str, dict]] = None,
) -> Optional[dict]:
    """EXACT whole-string lookup. This function is intentionally three lines
    long and intentionally boring: there is no startswith, no fnmatch, no
    rsplit-the-version-off, no .lower(), no .strip(). Any of those would turn
    one reviewed exemption into an open-ended family of unreviewed ones.
    """
    if allowlist is None:
        allowlist = load_external_layer_arn_allowlist()
    return allowlist.get(layer_arn)


def _inspect_one_layer(lambda_client, layer_arn: str, function_arch: str,
                        downloader: Callable[[str], bytes],
                        classify_so: Callable[[Path], Optional[str]],
                        self_account: Optional[str] = None) -> Tuple[str, str, str]:
    """Returns (state, reason_code, note) for one attached layer.

    `self_account` is the AWS account that owns the FUNCTION attaching this
    layer (parsed from its FunctionArn by check_layer_coherence). It is used
    for exactly one thing: telling "this layer lives in someone else's
    account" apart from "GetLayerVersion failed and we do not know why."
    When it is None the cross-account branch is skipped entirely rather than
    guessed at -- an unknown reference point cannot establish a difference.
    """
    # arn:aws:lambda:REGION:ACCOUNT:layer:NAME:VERSION
    parts = layer_arn.rsplit(":", 2)
    if len(parts) != 3:
        return UNKNOWN, "layer_arn_unparseable", f"{layer_arn}: could not parse layer name/version from ARN"
    layer_name, version_str = parts[1], parts[2]
    try:
        version = int(version_str)
    except ValueError:
        return UNKNOWN, "layer_arn_unparseable", f"{layer_arn}: non-numeric layer version {version_str!r}"

    try:
        lv = lambda_client.get_layer_version(LayerName=layer_name, VersionNumber=version)
    except Exception as exc:  # noqa: BLE001
        msg = _err(exc)
        # ENC-TSK-P09 / ENC-ISS-668: try the REAL check first, always -- the
        # register is a fallback for when it structurally cannot complete, not
        # a shortcut that shadows it. Consulted before the generic
        # permission_denied/layer_not_found branches so a documented external
        # dependency is never folded into either of those undifferentiated
        # buckets.
        # ENC-TSK-P18 / ENC-ISS-668, FIRST because it is the most specific and
        # the only REVIEWED signal: an exact, whole-string ARN match against
        # the governed component closure. This is the single branch that can
        # produce an attestable cross-account code, and it can only fire for
        # an ARN a human put in infrastructure/component_dependency_closure.json.
        allowlisted = lookup_allowlisted_layer_arn(layer_arn)
        if allowlisted is not None:
            declared = allowlisted.get("declared_arch")
            arch_note = ""
            if declared:
                arch_note = (
                    f" Declared arch={declared!r} vs function arch={function_arch!r} "
                    f"(informational only -- a declared fact is not inspected content, so "
                    f"this point stays unknown and is never promoted to pass).")
            return UNKNOWN, "external_dependency_cross_account_allowlisted", (
                f"{layer_arn}: GetLayerVersion could not complete ({msg}); this EXACT ARN is "
                f"declared in {allowlisted.get('source')} as dependency "
                f"{allowlisted.get('dependency_id')!r} of component "
                f"{allowlisted.get('component')!r} (owner account "
                f"{allowlisted.get('owner_account')}, owning_repository="
                f"{allowlisted.get('owning_repository')!r}). A cross-account permission "
                f"ceiling that has been reviewed and written down -- matched whole-string, "
                f"never by prefix or wildcard.{arch_note}")

        # ENC-TSK-P18 -- and SECOND, deliberately ahead of the name-keyed
        # register below. A layer sitting in another account that no exact-ARN
        # entry declares is an UNDECLARED ceiling. Letting it fall through to
        # EXTERNAL_LAYER_REGISTRY would let it inherit an attestable code from
        # a NAME its ARN happens to share -- e.g. a future
        # AWS-AppConfig-Extension-Arm64:999 nobody has reviewed collecting
        # :147's exemption. That is the silent over-admission ENC-TSK-P18's
        # negative control exists to keep impossible. Still distinct from
        # layer_not_found (AC-0: a ceiling reads as a ceiling), still UNKNOWN,
        # and pointedly NOT in ATTESTABLE_REASON_CODES.
        layer_account = _layer_arn_account(layer_arn)
        if layer_account and self_account and layer_account != self_account:
            return UNKNOWN, "cross_account_layer_unverifiable", (
                f"{layer_arn}: GetLayerVersion could not complete ({msg}); the layer is owned "
                f"by account {layer_account}, not this function's account {self_account} -- a "
                f"genuine cross-account ceiling, NOT a missing layer. No exact-ARN entry in "
                f"the governed component closure declares it, so it is NOT attestable: this "
                f"function's overall verdict stays plain unknown until either the ARN is "
                f"declared in infrastructure/component_dependency_closure.json or the layer "
                f"becomes independently readable.")

        registered = EXTERNAL_LAYER_REGISTRY.get(layer_name)
        if registered is not None:
            arch_note = ""
            if registered.get("declared_arch"):
                arch_note = (
                    f" Declared arch={registered['declared_arch']!r} vs function arch="
                    f"{function_arch!r} (informational only -- this point remains unknown; "
                    f"a declared fact about the layer's name is not independently verified "
                    f"content, so it is never promoted to pass)."
                )
            return UNKNOWN, registered["reason_code"], (
                f"{layer_arn}: GetLayerVersion could not complete ({msg}); resolved via the "
                f"external-dependency register instead of a generic layer_not_found -- "
                f"{registered['note']}{arch_note}")
        if "AccessDenied" in msg or "Forbidden" in msg or "403" in msg:
            return UNKNOWN, "permission_denied", f"{layer_arn}: GetLayerVersion denied: {msg}"
        if "ResourceNotFoundException" in msg or "404" in msg:
            return UNKNOWN, "layer_not_found", (
                f"{layer_arn}: GetLayerVersion could not find this layer version -- commonly a "
                f"cross-account AWS-managed layer that cannot be introspected from this account "
                f"(confirmed live for AWS-AppConfig-Extension-Arm64): {msg}")
        return UNKNOWN, "layer_not_found", f"{layer_arn}: could not read layer version: {msg}"

    compat_meta = lv.get("CompatibleArchitectures")
    url = (lv.get("Content") or {}).get("Location")
    if not url:
        return UNKNOWN, "layer_not_found", f"{layer_arn}: no Content.Location on layer version response"

    try:
        raw = downloader(url)
    except Exception as exc:  # noqa: BLE001
        return UNKNOWN, "layer_download_error", f"{layer_arn}: could not download layer content: {_err(exc)}"

    try:
        with tempfile.TemporaryDirectory(prefix="verify_arm64_layer_") as tmp:
            tmp_path = Path(tmp)
            zpath = tmp_path / "layer.zip"
            zpath.write_bytes(raw)
            with zipfile.ZipFile(zpath) as zf:
                zf.extractall(tmp_path / "content")
            mismatches, unknowns, so_count = _classify_so_tree(
                tmp_path / "content", function_arch, classify_so)
            if so_count == 0:
                return PASS, "layer_contents_verified", (
                    f"{layer_arn}: zero .so files -- genuinely architecture-neutral "
                    f"(CompatibleArchitectures metadata={compat_meta}, not relied on)")

            if mismatches:
                return FAIL, "compiled_object_mismatch", (
                    f"{layer_arn}: {len(mismatches)} compiled object(s) do not match function "
                    f"arch {function_arch!r}: {', '.join(mismatches[:5])} "
                    f"(CompatibleArchitectures metadata={compat_meta} was NOT trusted, "
                    f"per BRD 6.5 -- and would have hidden this)")
            if unknowns:
                return UNKNOWN, "layer_content_unclassifiable", (
                    f"{layer_arn}: {len(unknowns)} compiled object(s) could not be classified: "
                    f"{', '.join(unknowns[:5])}")
            return PASS, "layer_contents_verified", (
                f"{layer_arn}: {so_count} compiled object(s), all match function arch "
                f"{function_arch!r} (inspected, not inferred from metadata={compat_meta})")
    except zipfile.BadZipFile as exc:
        return UNKNOWN, "bad_layer_zip", f"{layer_arn}: downloaded content is not a valid zip: {exc}"


def check_layer_coherence(
    lambda_client, function_name: str,
    downloader: Callable[[str], bytes] = _default_downloader,
    classify_so: Optional[Callable[[Path], Optional[str]]] = None,
) -> PointResult:
    if classify_so is None:
        classify_so = _load_classify_so()

    try:
        cfg = lambda_client.get_function_configuration(FunctionName=function_name)
    except Exception as exc:  # noqa: BLE001
        return PointResult(2, "layer_coherence", UNKNOWN,
                            f"could not read function configuration: {_err(exc)}",
                            reason_code="config_read_error")

    actual_arch = (cfg.get("Architectures") or ["unknown"])[0]
    layers = cfg.get("Layers") or []
    # ENC-TSK-P18: the account that owns THIS function, used only as the
    # reference point for "is that layer in a different account." Parsed from
    # the live FunctionArn; None (and therefore no cross-account claim) when
    # the response does not carry one.
    function_arn = cfg.get("FunctionArn") or ""
    arn_fields = function_arn.split(":")
    self_account = arn_fields[4] if len(arn_fields) >= 6 and arn_fields[4].isdigit() else None

    if not layers:
        return PointResult(2, "layer_coherence", PASS,
                            "function declares zero layers -- vacuously coherent "
                            "(ENC-TSK-O70: this is a legitimate, deliberate state, not a gap)",
                            reason_code="zero_layers")

    notes: List[str] = []
    fail_reason: Optional[str] = None
    unknown_reason: Optional[str] = None
    for layer in layers:
        arn = layer.get("Arn", "")
        state, reason, note = _inspect_one_layer(lambda_client, arn, actual_arch, downloader,
                                                  classify_so, self_account)
        notes.append(note)
        if state == FAIL and fail_reason is None:
            fail_reason = reason
        elif state == UNKNOWN and unknown_reason is None:
            unknown_reason = reason

    if fail_reason is not None:
        overall, overall_reason = FAIL, fail_reason
    elif unknown_reason is not None:
        overall, overall_reason = UNKNOWN, unknown_reason
    else:
        overall, overall_reason = PASS, "layer_contents_verified"
    return PointResult(2, "layer_coherence", overall, " | ".join(notes), reason_code=overall_reason)


# ---------------------------------------------------------------------------
# Point 3 -- live invocation
# ---------------------------------------------------------------------------

def check_live_invocation(lambda_client, function_name: str, payload: str = "{}") -> PointResult:
    try:
        resp = lambda_client.invoke(FunctionName=function_name, Payload=payload.encode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        msg = _err(exc)
        if "AccessDeniedException" in msg or "not authorized to perform: lambda:InvokeFunction" in msg:
            return PointResult(3, "live_invocation", UNKNOWN,
                                f"IAM identity lacks lambda:InvokeFunction on {function_name} "
                                f"(confirmed live under AWS_PROFILE=enceladus-agent, 2026-08-23) -- "
                                f"cannot prove or disprove liveness under this credential; "
                                f"this is NOT a pass",
                                reason_code="permission_denied")
        if "ResourceNotFoundException" in msg:
            return PointResult(3, "live_invocation", FAIL, f"function {function_name} does not exist: {msg}",
                                reason_code="function_not_found")
        return PointResult(3, "live_invocation", UNKNOWN, f"invoke call errored: {msg}",
                            reason_code="invoke_error")

    body = b""
    try:
        payload_stream = resp.get("Payload")
        if payload_stream is not None:
            body = payload_stream.read()
    except Exception as exc:  # noqa: BLE001
        return PointResult(3, "live_invocation", UNKNOWN, f"invoke succeeded but response body unreadable: {_err(exc)}",
                            reason_code="response_unreadable")

    if resp.get("FunctionError"):
        text = body.decode("utf-8", "replace")
        return PointResult(3, "live_invocation", FAIL,
                            f"FunctionError={resp['FunctionError']}: {text[:400]} "
                            f"-- native-wheel import failure is the most likely arm64 failure mode here",
                            reason_code="function_error")

    return PointResult(3, "live_invocation", PASS,
                        f"StatusCode={resp.get('StatusCode')}, response={body[:200]!r}",
                        reason_code="invoked_ok")


# ---------------------------------------------------------------------------
# Point 4 -- integration edge (pluggable per-function probe)
#
# REPAIRED under ENC-TSK-P08/ENC-ISS-665 -- see the module docstring's "THE
# FIVE POINTS" entry for point 4 and its "O96/ATTESTED VS ENC-ISS-665"
# section before changing anything below. The concrete defect: the probe used
# to read a single CloudWatch log stream mid-flight, before an ERROR/Traceback
# had been written, and measure "freshness" against point 3's OWN invocation
# from seconds earlier in the same run -- manufacturing the freshness it then
# accepted. Four remedies now hold at once:
#   1. Run-start freshness anchoring   -- _evaluate_schedule_window / the
#      "run_start_ms" anchor threaded through clients.
#   2. Terminated-invocation requirement -- _evaluate_schedule_window's
#      REPORT/END check, plus the bounded poll-and-retry loop in
#      _probe_governance_mart_schedule (UNKNOWN on timeout, never PASS).
#   3. Cross-point contradiction assertion (LOAD-BEARING) --
#      _enforce_no_pass_when_point3_failed, applied unconditionally by
#      check_integration_edge. This does not look at logs, timestamps, or
#      streams at all -- it only compares two already-computed verdicts, so
#      it holds even if remedies 1, 2 and 4 are absent or regressed.
#   4. Log-group-wide evaluation -- _fetch_log_group_window uses
#      filter_log_events (merges every stream in the group by time) instead
#      of describe_log_streams(limit=1) (a single "latest" stream a
#      concurrent invocation could hide behind).
# ---------------------------------------------------------------------------

# A probe receives (function_name, clients) where clients is a dict of
# already-constructed boto3 clients (e.g. {"logs": ..., "lambda": ...,
# "run_start_ms": <float, epoch ms captured before point 3 ran>}), and must
# return (state, detail) with state in PASS/FAIL/UNKNOWN. Never PASS by
# default -- a missing probe is UNKNOWN, not a pass (BRD 8.4: function green
# is not system green).
IntegrationProbe = Callable[[str, Dict[str, object]], Tuple[str, str]]
PROBE_REGISTRY: Dict[str, IntegrationProbe] = {}

# ENC-ISS-678: every probe must DECLARE the downstream it asserts against, as
# the environment-variable key(s) through which the target function names that
# downstream in its own configuration. PROBE_CONTRACTS[function_name] is that
# declaration, and _verify_probe_contract enforces it BEFORE the probe runs.
#
# WHY THIS EXISTS. register_probe used to be a bare name->callable map, which
# cannot express "this probe belongs to this function" and therefore cannot be
# reviewed for it. _probe_governance_mart was registered for FOUR names, two of
# which (devops-recompute-governance[-gamma]) do not write the mart at all --
# they write a DynamoDB governance-version record. The mart parquet those two
# were being judged on is written by a DIFFERENT function, so a dead
# recompute-governance would still have scored PASS on the mart's output.
#
# That is a FALSE ATTRIBUTION, and it is the ENC-ISS-665 family in a fourth
# shape: 665 passed on state it created itself, 675 failed on an enumeration it
# truncated, 677 certified completeness it did not have, and this one passes on
# state SOMEONE ELSE created. All four substitute an observable merely
# CORRELATED with health for the one that IS health.
#
# A mismatch is UNKNOWN, never PASS and never FAIL -- the harness cannot claim
# the edge is broken when what it has actually established is that it was
# pointed at the wrong edge.
PROBE_CONTRACTS: Dict[str, Tuple[str, ...]] = {}


def register_probe(
    *function_names: str, declares: Tuple[str, ...] = (),
) -> Callable[[IntegrationProbe], IntegrationProbe]:
    """Register `fn` as the point-4 probe for each name in `function_names`.

    `declares` names the environment variable(s) through which the target
    function must itself reference the downstream this probe asserts against.
    An empty `declares` is permitted only for probes whose downstream is not
    expressible as a function environment variable (e.g. the API Gateway route
    topology, which lives in the API's configuration and not the function's) --
    those state their justification at the registration site.
    """
    def deco(fn: IntegrationProbe) -> IntegrationProbe:
        for name in function_names:
            PROBE_REGISTRY[name] = fn
            PROBE_CONTRACTS[name] = tuple(declares)
        return fn
    return deco


def _verify_probe_contract(
    function_name: str, clients: Dict[str, object],
) -> Optional[Tuple[str, str]]:
    """Confirm the registered probe's declared downstream is one THIS function
    actually references. Returns None when the contract holds, else a
    (reason_code, detail) pair for an UNKNOWN verdict.

    Fail-safe by construction: an unreadable configuration yields
    probe_contract_unverifiable, never a silent pass. Neither returned reason
    code is in ATTESTABLE_REASON_CODES -- a probe pointed at the wrong resource
    is a measurement defect, not a declared external ceiling, and must not be
    laundered into looking like one.
    """
    required = PROBE_CONTRACTS.get(function_name) or ()
    if not required:
        return None
    lambda_client = clients.get("lambda")
    if lambda_client is None:
        return ("probe_contract_unverifiable",
                f"probe for {function_name!r} declares downstream env key(s) "
                f"{', '.join(required)} but no lambda client was supplied to confirm the "
                f"function actually references them -- refusing to run a probe whose "
                f"attribution to this function cannot be checked (ENC-ISS-678)")
    try:
        cfg = lambda_client.get_function_configuration(FunctionName=function_name)
    except Exception as exc:  # noqa: BLE001
        return ("probe_contract_unverifiable",
                f"could not read configuration for {function_name!r} to confirm it references "
                f"the declared downstream env key(s) {', '.join(required)}: {_err(exc)}")
    env = ((cfg or {}).get("Environment") or {}).get("Variables") or {}
    missing = [k for k in required if not env.get(k)]
    if missing:
        return ("probe_contract_mismatch",
                f"PROBE MISATTRIBUTION REFUSED: the probe registered for {function_name!r} "
                f"asserts a downstream this function does not reference. It declares env key(s) "
                f"{', '.join(required)}, but {', '.join(missing)} is absent from the function's "
                f"own configuration (present: {', '.join(sorted(env)) or 'none'}). Running it "
                f"would judge {function_name!r} on an artifact written by something else -- a "
                f"false PASS in the lenient direction (ENC-ISS-678). Reported UNKNOWN: the edge "
                f"is not established broken, it is not established at all.")
    return None


_REQUEST_ID_MARKER_RE = re.compile(r"RequestId:\s*([0-9a-fA-F-]{8,})")


def _fetch_log_group_window(logs_client, log_group: str, start_ms: float, end_ms: float) -> List[dict]:
    """REMEDY 4 (log-group-wide evaluation): uses filter_log_events, which
    merges events across EVERY stream in the log group ordered by time,
    instead of describe_log_streams(limit=1) picking one single "latest"
    stream. A concurrent invocation (this harness's own point-3 invoke racing
    a real scheduled firing, or two overlapping scheduled firings) can land in
    a different stream -- describe_log_streams(limit=1) can then return the
    wrong stream entirely and never even fetch the one that matters. This
    function cannot exhibit that failure mode: it does not pick a stream.

    start_ms/end_ms bound the query -- end_ms is normally the harness's
    run-start anchor (remedy 1), never "now".
    """
    events: List[dict] = []
    kwargs: Dict[str, object] = {
        "logGroupName": log_group, "startTime": int(start_ms), "endTime": int(end_ms), "limit": 1000,
    }
    for _ in range(5):  # bounded pagination -- this is a freshness probe, not a full export
        resp = logs_client.filter_log_events(**kwargs)
        events.extend(resp.get("events", []))
        token = resp.get("nextToken")
        if not token:
            break
        kwargs["nextToken"] = token
    return events


def _group_invocations(events: List[dict]) -> Dict[str, dict]:
    """Group log-group-wide events by RequestId so each invocation's
    lifecycle (terminated? erred?) is judged as a whole, never from one line
    read out of context -- the ENC-ISS-665 defect was exactly reading a
    single line before its invocation had finished writing.
    """
    invocations: Dict[str, dict] = {}
    for e in events:
        msg = e.get("message", "") or ""
        ts = e.get("timestamp", 0) or 0
        m = _REQUEST_ID_MARKER_RE.search(msg)
        if not m:
            continue
        rid = m.group(1)
        inv = invocations.setdefault(rid, {"terminated": False, "error": False, "last_ts": ts})
        inv["last_ts"] = max(inv["last_ts"], ts)
        if msg.startswith("REPORT RequestId") or msg.startswith("END RequestId"):
            inv["terminated"] = True
        if "ERROR" in msg or "Traceback" in msg:
            inv["error"] = True
    return invocations


def _log_group_has_any_stream(logs_client, log_group: str) -> Optional[bool]:
    """Cheap existence check, independent of the freshness window, so an empty
    in-window result can be told apart from "this function has never run" --
    the two need different verdicts (unknown vs. fail)."""
    try:
        resp = logs_client.describe_log_streams(logGroupName=log_group, limit=1)
    except Exception:  # noqa: BLE001
        return None
    return bool(resp.get("logStreams"))


def _evaluate_schedule_window(
    events: List[dict], *, now_ms: float, run_start_ms: float, max_age_hours: float,
) -> Tuple[str, str, str]:
    """Pure, AWS-free evaluation of a log-group-wide event window. Returns
    (state, signal, detail); `signal` is "not_terminated" exactly when the
    caller's bounded poll-and-retry (remedy 2) should apply, and is otherwise
    just an internal label -- it is NOT a PointResult.reason_code.

    REMEDY 1 (run-start anchoring) is RE-ASSERTED here, not only at the query
    boundary in _fetch_log_group_window: any event at or after run_start_ms is
    dropped before it can influence the verdict, even if a caller's query
    bounds regress and over-fetch. This is the exact ENC-ISS-665 defect
    surface: the difference between "the schedule has been healthy" and
    "point 3's own invocation, seconds old, looks clean so far."

    REMEDY 2 (terminated-invocation requirement): an ERROR/Traceback line,
    once observed, is decisive evidence immediately -- no need to wait for a
    REPORT/END line to believe an exception was logged. But the ABSENCE of an
    error is only trustworthy once the invocation has terminated; an
    invocation with no error line yet and no REPORT/END line is exactly the
    shape of the original defect (read before the error had been written) and
    must be UNKNOWN, never PASS.

    REMEDY 4 (log-group-wide): every invocation found in-window is scanned for
    errors, not just the single most-recent one by timestamp -- so a
    concurrent invocation sitting in a different, slightly-older stream cannot
    hide an error behind a clean newer one.
    """
    events = [e for e in events if (e.get("timestamp", 0) or 0) < run_start_ms]
    if not events:
        return UNKNOWN, "no_activity", (
            "no log-group activity found predating this harness run within the schedule "
            "window -- cannot distinguish a stopped cron from a function with no history yet")

    invocations = _group_invocations(events)
    if not invocations:
        return UNKNOWN, "unparseable", (
            f"{len(events)} log event(s) found in-window but none carried a recognizable "
            f"RequestId START/END/REPORT marker")

    erroring = [(rid, inv) for rid, inv in invocations.items() if inv["error"]]
    if erroring:
        rid, inv = max(erroring, key=lambda kv: kv[1]["last_ts"])
        age_hours = (now_ms - inv["last_ts"]) / 3_600_000.0
        return FAIL, "error_found", (
            f"invocation {rid} contains an ERROR/Traceback line ({age_hours:.1f}h old; found "
            f"scanning {len(invocations)} invocation(s) log-group-wide across the schedule "
            f"window, not just the single newest stream -- ENC-ISS-665 remedy 4). An observed "
            f"error line is decisive regardless of whether its REPORT/END line has been "
            f"written yet.")

    latest_rid = max(invocations, key=lambda r: invocations[r]["last_ts"])
    latest = invocations[latest_rid]
    age_hours = (now_ms - latest["last_ts"]) / 3_600_000.0

    if not latest["terminated"]:
        return UNKNOWN, "not_terminated", (
            f"most recent PRE-RUN invocation ({latest_rid}) has no REPORT/END line yet and "
            f"shows no error either -- refusing to classify an unterminated invocation as a "
            f"pass (ENC-ISS-665 remedy 2); this is exactly the shape of the original defect: "
            f"reading a stream before its ERROR/Traceback had been written")

    if age_hours > max_age_hours:
        return FAIL, "stale", (
            f"most recent PRE-RUN invocation ({latest_rid}), terminated, last wrote "
            f"{age_hours:.1f}h ago (> {max_age_hours}h schedule window) -- DVP-ISS-103 class: "
            f"a stopped cron is silent without this check")

    return PASS, "clean", (
        f"most recent PRE-RUN invocation ({latest_rid}) terminated {age_hours:.1f}h ago with "
        f"no ERROR/Traceback, and none of the other {len(invocations) - 1} invocation(s) found "
        f"log-group-wide in this window showed one either (evaluated strictly before this "
        f"harness run started -- ENC-ISS-665 remedies 1 and 4)")


# ENC-TSK-P19: this probe is NO LONGER registered directly. It checks one half
# of BRD 8.4's worked example -- "on its schedule" -- and ENC-TSK-P19 AC-0
# requires the other half, "the mart must PRODUCE a mart," which schedule
# freshness cannot see: a run can fire on time, log nothing alarming, and
# still write no mart. _probe_governance_mart below composes the two and is
# what PROBE_REGISTRY now maps those four names to. This function is unchanged
# and still directly unit-tested.
def _probe_governance_mart_schedule(
    function_name: str, clients: Dict[str, object], max_age_hours: float = 26.0, *,
    poll_attempts: int = 3, poll_interval_s: float = 2.0,
    sleep: Callable[[float], None] = time.sleep,
) -> Tuple[str, str]:
    """Demonstration probe for BRD 8.4's own example: 'the mart must produce a
    mart on its schedule.' Checks CloudWatch Logs, log-group-wide, for a
    terminated invocation predating this harness run whose events contain no
    ERROR/Traceback line. This is the DVP-ISS-103 class of failure: a
    scheduled job can stop firing entirely and be invisible to every
    function-level check that only asks 'does invoke succeed.'

    See _evaluate_schedule_window for remedies 1, 2 and 4. Remedy 3 (the
    load-bearing cross-point contradiction assertion) does NOT live here --
    it is applied unconditionally by check_integration_edge regardless of
    what this probe returns, specifically so it holds even if this probe
    regresses.
    """
    logs_client = clients.get("logs")
    if logs_client is None:
        return UNKNOWN, "no logs client provided to probe"

    run_start_ms = clients.get("run_start_ms")
    if run_start_ms is None:
        # Best-effort only: evaluate_function always supplies this, captured
        # before point 3 runs. A direct caller that omits it loses remedy 1's
        # guarantee -- documented, not silently patched over.
        run_start_ms = time.time() * 1000.0

    log_group = f"/aws/lambda/{function_name}"
    window_start_ms = run_start_ms - max_age_hours * 3_600_000.0

    state = detail = None
    for attempt in range(max(1, poll_attempts)):
        try:
            events = _fetch_log_group_window(logs_client, log_group, window_start_ms, run_start_ms)
        except Exception as exc:  # noqa: BLE001
            return UNKNOWN, f"could not read {log_group}: {_err(exc)}"

        if not events:
            has_ever_run = _log_group_has_any_stream(logs_client, log_group)
            if has_ever_run is None:
                return UNKNOWN, f"could not confirm whether {log_group} has ever produced logs"
            if not has_ever_run:
                return UNKNOWN, f"{log_group} has no log streams at all -- cannot tell whether it has ever run"
            return FAIL, (
                f"{log_group}: no activity found predating this harness run within the "
                f"{max_age_hours}h schedule window (the log group has prior streams, so this "
                f"is staleness, not a never-run function) -- DVP-ISS-103 class: a stopped cron "
                f"is silent without this check")

        now_ms = time.time() * 1000.0
        state, signal, detail = _evaluate_schedule_window(
            events, now_ms=now_ms, run_start_ms=run_start_ms, max_age_hours=max_age_hours)
        if signal != "not_terminated":
            return state, detail
        if attempt < poll_attempts - 1:
            sleep(poll_interval_s)

    # REMEDY 2's other half: bounded-timeout poll gives up without ever
    # escalating to PASS.
    return UNKNOWN, f"{detail} (gave up after {poll_attempts} attempt(s), still unterminated)"


# ---------------------------------------------------------------------------
# ENC-TSK-P19 / ENC-ISS-665 -- probe coverage, and declared devops ownership.
#
# The first fleet run registered probes for 2 of 51 functions, so point 4 was
# unknown for 49. ENC-TSK-P08 is NOT the fix for that and must not be read as
# one: re-reading its diff, it repaired the self-fulfilling freshness signal
# (remedy 1, run-start anchoring), the mid-flight log race (remedies 2 and 4),
# and added the cross-point contradiction assertion (remedy 3). Every one of
# those makes the EXISTING probe honest. None of them registers a new probe,
# and DOC-868BC8DFB349 warns explicitly against assuming otherwise.
# ---------------------------------------------------------------------------

# The two routes the escalation decision authorizer must guard. BOTH, not
# either: an authorizer wired to /approve but not /deny leaves the deny path
# unauthenticated, and a function-level check ("does the Lambda exist, does it
# invoke") cannot see the difference -- which is exactly BRD 8.4's "function
# green is not system green."
ESCALATION_ROUTE_SUFFIXES = ("/approve", "/deny")
ESCALATION_ROUTE_MARKER = "/escalations/"

MART_BUCKET_DEFAULT = "devops-agentcli-compute"
MART_KEY_PREFIX_DEFAULT = "warehouse/devops/"
MART_DATA_OBJECT_NAME = "data.parquet"

DEVOPS_OWNERSHIP_SNAPSHOT_RELPATH = "infrastructure/devops_lambda_ownership_snapshot.json"


def _devops_owned_names() -> Tuple[Optional[set], List[str]]:
    """(names, errors) from ENC-TSK-P15's pinned ownership snapshot.

    Reuses tools/verify_lambda_arch_parity.py's loader and predicate rather
    than reimplementing them -- ENC-TSK-P15's explicit instruction is not to
    build a second ownership mechanism, and a second one would be a second
    thing that can disagree. Imported lazily so this harness keeps importing
    cleanly (and its self-tests keep running) in an environment where that
    module's own optional dependencies are unavailable.

    THE PREDICATE IS EXACT NAME MATCH, NEVER A PREFIX. enceladus owns dozens
    of its own functions whose names begin with "devops-" (devops-governance-
    mart, devops-recompute-governance, ... -- both declared in this repo's
    infrastructure/lambda_workflow_manifest.json with
    owning_repository=NX-2021-L/enceladus). A startswith("devops-") predicate
    would hand every one of them a NOT_APPLICABLE exemption and switch off
    point 4 for the very functions ENC-ISS-667 caught running dead.
    """
    try:
        sys.path.insert(0, str(TOOLS_DIR))
        import verify_lambda_arch_parity as _arch_parity  # noqa: PLC0415
    except Exception as exc:  # noqa: BLE001
        return None, [f"could not import the ownership predicate: {_err(exc)}"]
    try:
        snapshot, errors = _arch_parity._load_devops_ownership_snapshot()
        if errors or snapshot is None:
            return None, errors or ["ownership snapshot could not be loaded"]
        return _arch_parity._devops_owned_function_names(snapshot), []
    except Exception as exc:  # noqa: BLE001
        return None, [f"ownership predicate raised: {_err(exc)}"]


def _resolve_devops_ownership(function_name: str) -> Optional[PointResult]:
    """A declared point-4 answer for a NX-2021-L/devops-owned function, or None.

    io's standing ruling, applied at the harness level: a devops-owned
    resource is outside enceladus deploy validation. The answer is DECLARED --
    NOT_APPLICABLE_ON_PLANE, carrying the ownership rationale and the file it
    came from -- rather than probed or skipped.

    THE GATE STILL FIRES. This is not `if devops: return` and it is not a name
    removed from a list. It runs on every function, every run, and writes a
    recorded verdict either way, because a removed check is silence, and
    silence is what let a mart run dead and a schedule stop for fifteen days
    (DVP-ISS-103, ENC-ISS-667) with every dashboard green. An unreadable
    declaration is likewise an UNKNOWN that says so, never an assumed
    "not devops" that quietly resumes probing someone else's estate.
    """
    names, errors = _devops_owned_names()
    if names is None:
        return PointResult(
            4, "integration_edge", UNKNOWN,
            f"the devops ownership declaration ({DEVOPS_OWNERSHIP_SNAPSHOT_RELPATH}) could not "
            f"be read, so {function_name!r} cannot be resolved to NOT_APPLICABLE_ON_PLANE or "
            f"confidently probed as enceladus-owned: {'; '.join(errors)}",
            reason_code="devops_ownership_declaration_unreadable")
    if function_name not in names:  # EXACT match. Never a prefix.
        return None
    return PointResult(
        4, "integration_edge", UNKNOWN,
        f"NOT_APPLICABLE_ON_PLANE: {function_name!r} appears by EXACT name match in "
        f"{DEVOPS_OWNERSHIP_SNAPSHOT_RELPATH}'s functions[], the pinned, hash-verified "
        f"declaration of NX-2021-L/devops's own Lambda estate (ENC-TSK-P15). Per io's "
        f"standing ruling a devops-owned resource is outside enceladus deploy validation, so "
        f"this plane asserts nothing about its downstream contract. This is a DECLARED "
        f"answer, not a skip -- the gate fired and recorded it -- and it is not a pass: the "
        f"point stays unknown and the function can reach at most ATTESTED.",
        reason_code="not_applicable_on_plane_devops_owned")


def _paginate_v2(fn, item_key: str = "Items", **kwargs) -> Tuple[Optional[List[dict]], Optional[str]]:
    """Drain every page of an apigatewayv2 list call. (items, error).

    ENC-TSK-P20. apigatewayv2 get_routes returns a BOUNDED FIRST PAGE -- 25 of
    184 routes on the gamma API in practice -- and the boundary is not an error
    the caller can see. Reading only that page made this probe report
    FAIL/"no escalation route found for /deny" on an API where the deny route
    exists and is correctly guarded by the same authorizer as /approve.

    THAT IS A FALSE FAIL, AND IT IS THE MIRROR IMAGE OF THE ENC-ISS-665 VACUOUS
    PASS, NOT ITS OPPOSITE. A check that reports FAIL because it could not see
    everything is exactly as untrustworthy as one that reports PASS because it
    did not look -- both substitute the reach of the query for the state of the
    world. A verdict is only worth its enumeration.

    Errors are RETURNED rather than raised so the caller can answer UNKNOWN. An
    enumeration that could not complete must never collapse into a determinate
    verdict in either direction.
    """
    items: List[dict] = []
    next_token = None
    for _ in range(50):  # bounded: a runaway NextToken must not hang the harness
        call_kwargs = dict(kwargs)
        call_kwargs["MaxResults"] = "500"
        if next_token:
            call_kwargs["NextToken"] = next_token
        try:
            resp = fn(**call_kwargs)
        except Exception as exc:  # noqa: BLE001
            return None, _err(exc)
        items.extend(resp.get(item_key) or [])
        next_token = resp.get("NextToken")
        if not next_token:
            return items, None
    return None, "pagination did not terminate within 50 pages"


# declares=() is deliberate and justified: this probe's downstream is the API
# Gateway ROUTE TOPOLOGY, which lives in the API's configuration rather than in
# the function's environment. The probe establishes attribution directly and
# more strongly than an env key could -- it resolves each route's AuthorizerId
# and confirms that authorizer's AuthorizerUri references THIS function.
@register_probe("escalation-decision-authorizer", "escalation-decision-authorizer-gamma",
                declares=())
def _probe_escalation_authorizer_routes(
    function_name: str, clients: Dict[str, object],
) -> Tuple[str, str]:
    """ENC-TSK-P19 AC-0 / ENC-TSK-O90 AC-1: is this authorizer actually
    attached to BOTH the approve AND the deny route?

    backend/lambda/escalation_decision_authorizer/lambda_function.py exists
    "for the escalation approve/deny decision routes only." Nothing about the
    Lambda's own state -- its architecture, its layers, whether it invokes --
    tells you whether API Gateway routes traffic through it, or through it on
    only ONE of the two routes. An authorizer on /approve but not /deny is a
    live authorization hole that every function-level point in this harness
    reports as perfectly healthy. That gap is the whole reason point 4 exists.
    """
    api_client = clients.get("apigatewayv2")
    if api_client is None:
        return UNKNOWN, ("no apigatewayv2 client supplied -- route attachment cannot be read, "
                         "so this probe asserts nothing (it does not pass by default)")
    apis, apis_err = _paginate_v2(api_client.get_apis)
    if apis_err is not None:
        return UNKNOWN, f"could not list HTTP APIs (apigatewayv2:GetApis): {apis_err}"

    found: Dict[str, dict] = {}
    for api in apis:
        api_id = api.get("ApiId")
        if not api_id:
            continue
        routes, routes_err = _paginate_v2(api_client.get_routes, ApiId=api_id)
        if routes_err is not None:
            return UNKNOWN, f"could not list routes on API {api_id}: {routes_err}"
        for route in routes:
            route_key = route.get("RouteKey") or ""
            if ESCALATION_ROUTE_MARKER not in route_key:
                continue
            for suffix in ESCALATION_ROUTE_SUFFIXES:
                if route_key.endswith(suffix):
                    found[suffix] = {"api_id": api_id, "route": route, "route_key": route_key}

    missing = [sfx for sfx in ESCALATION_ROUTE_SUFFIXES if sfx not in found]
    if missing:
        return FAIL, (
            f"{function_name}: no escalation route found for {', '.join(missing)} across "
            f"{len(apis)} HTTP API(s) -- the decision route this authorizer exists to guard "
            f"is not present, so nothing is guarding it")

    unguarded: List[str] = []
    guarded: List[str] = []
    for suffix, hit in found.items():
        authorizer_id = hit["route"].get("AuthorizerId")
        if not authorizer_id:
            unguarded.append(f"{hit['route_key']} (no AuthorizerId at all)")
            continue
        try:
            authorizer = api_client.get_authorizer(ApiId=hit["api_id"], AuthorizerId=authorizer_id)
        except Exception as exc:  # noqa: BLE001
            return UNKNOWN, (f"route {hit['route_key']} has AuthorizerId={authorizer_id} but it "
                             f"could not be read: {_err(exc)}")
        uri = authorizer.get("AuthorizerUri") or ""
        if function_name in uri:
            guarded.append(hit["route_key"])
        else:
            unguarded.append(
                f"{hit['route_key']} (authorizer {authorizer.get('Name')!r} does not resolve to "
                f"{function_name})")

    if unguarded:
        return FAIL, (
            f"{function_name}: guarded {guarded or 'NOTHING'}, but NOT {'; '.join(unguarded)} -- "
            f"an escalation decision route that this authorizer does not front is a route where "
            f"the approver allowlist is never consulted. Asymmetric coverage across approve/deny "
            f"is invisible to every function-level check")
    return PASS, (
        f"{function_name} fronts BOTH escalation decision routes: {', '.join(sorted(guarded))} "
        f"(each route's AuthorizerId resolved and its AuthorizerUri references this function)")


def _probe_governance_mart_produced(
    function_name: str, clients: Dict[str, object], max_age_hours: float = 26.0, *,
    bucket: str = MART_BUCKET_DEFAULT, prefix: str = MART_KEY_PREFIX_DEFAULT,
) -> Tuple[str, str]:
    """ENC-TSK-P19 AC-0, the half schedule freshness cannot see: did the mart
    actually PRODUCE a mart?

    BRD 8.4's worked example is "the mart must produce a mart on its
    schedule." _probe_governance_mart_schedule reads the second clause. This
    one reads the first, against the artifact itself: backend/lambda/
    governance_mart/mart_schema.py writes to
    s3://<bucket>/warehouse/devops/<table>/data.parquet. A run that fires on
    time, exits cleanly, logs no traceback and writes nothing at all is
    indistinguishable from a healthy one to every check that only reads logs.
    """
    s3_client = clients.get("s3")
    if s3_client is None:
        return UNKNOWN, "no s3 client supplied -- mart production cannot be read"

    run_start_ms = clients.get("run_start_ms")
    if run_start_ms is None:
        run_start_ms = time.time() * 1000.0

    try:
        resp = s3_client.list_objects_v2(Bucket=bucket, Prefix=prefix)
    except Exception as exc:  # noqa: BLE001
        msg = _err(exc)
        if "AccessDenied" in msg or "Forbidden" in msg or "403" in msg:
            return UNKNOWN, (f"s3:ListBucket denied on s3://{bucket}/{prefix} -- this identity "
                             f"cannot see whether a mart was produced; that is a permission "
                             f"ceiling, not a pass")
        if "NoSuchBucket" in msg:
            return FAIL, (f"s3://{bucket} does not exist -- the mart has nowhere to write "
                          f"(ENC-TSK-O95 class: a bucket removed while its producer stayed "
                          f"deployed and enabled)")
        return UNKNOWN, f"could not list s3://{bucket}/{prefix}: {msg}"

    objects = [o for o in (resp.get("Contents") or [])
               if str(o.get("Key", "")).endswith(MART_DATA_OBJECT_NAME)]
    if not objects:
        return FAIL, (
            f"{function_name}: zero {MART_DATA_OBJECT_NAME} objects under "
            f"s3://{bucket}/{prefix} -- the mart produced no mart. A schedule-only check "
            f"cannot see this: the run can fire on time and write nothing")

    def _epoch_ms(obj: dict) -> float:
        last = obj.get("LastModified")
        if hasattr(last, "timestamp"):
            return float(last.timestamp()) * 1000.0
        return 0.0

    newest = max(objects, key=_epoch_ms)
    age_hours = (float(run_start_ms) - _epoch_ms(newest)) / 3_600_000.0
    if age_hours > max_age_hours:
        return FAIL, (
            f"{function_name}: newest mart object s3://{bucket}/{newest.get('Key')} was written "
            f"{age_hours:.1f}h before this run started (> {max_age_hours}h) -- the mart exists "
            f"but is stale; production has stopped")
    return PASS, (
        f"{function_name}: {len(objects)} mart object(s) under s3://{bucket}/{prefix}; newest "
        f"({newest.get('Key')}) written {age_hours:.1f}h before this run started, inside the "
        f"{max_age_hours}h window")


# ENC-ISS-678: devops-recompute-governance[-gamma] WAS registered here and is
# not any more. It does not write the mart -- it is the sole writer of the
# governance-version DynamoDB record (02-compute.yaml RecomputeGovernanceFunction:
# "Triggered by S3 ObjectCreated on governance/live/*; writes canonical
# governance-version DDB record. IAM sole-writer grant (I28)"). Its probe is
# _probe_governance_version_record below. `declares` pins this probe to the
# MART_BUCKET env key, which the mart function carries and recompute-governance
# does not -- so the misattribution is now mechanically detectable, not merely
# absent by review.
@register_probe("devops-governance-mart", "devops-governance-mart-gamma",
                declares=("MART_BUCKET",))
def _probe_governance_mart(function_name: str, clients: Dict[str, object]) -> Tuple[str, str]:
    """Composite: BRD 8.4's example has two clauses and this checks both.

    Combination is worst-wins -- FAIL beats UNKNOWN beats PASS -- so neither
    half can cover for the other. A fresh schedule with no output is a FAIL,
    and a fresh output with a dead schedule is a FAIL, and only both-clean is
    a PASS. Combining them the other way (either-passes) would rebuild the
    exact vacuity this point exists to eliminate.
    """
    schedule_state, schedule_detail = _probe_governance_mart_schedule(function_name, clients)
    produced_state, produced_detail = _probe_governance_mart_produced(function_name, clients)
    detail = f"schedule: {schedule_detail} || production: {produced_detail}"
    for worst in (FAIL, UNKNOWN):
        if worst in (schedule_state, produced_state):
            return worst, detail
    return PASS, detail


_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_GOVERNANCE_VERSION_CANONICAL_KEY = "governance-version-current"


# ENC-ISS-678 / ENC-TSK-P26. The real downstream contract for
# devops-recompute-governance[-gamma], replacing the mart probe that was
# mis-registered for it.
#
# WHY THIS PROBE ASSERTS STRUCTURE AND NOT FRESHNESS, which is the whole design
# decision and the easiest thing for a successor to "fix" wrongly. This function
# is S3-EVENT-DRIVEN (ObjectCreated on governance/live/*) with an hourly
# backstop. When no governance file changes, the correct behaviour is to write
# NOTHING, and the canonical record legitimately sits untouched for weeks -- it
# was observed at updated_at 2026-08-01, twenty-two days old, on a healthy
# system. A freshness window here would manufacture a FAIL out of correct
# quiescence: the ENC-ISS-675 defect with the sign flipped, an enumeration-style
# false negative produced by measuring the wrong property rather than by reading
# too little. Age is not evidence for an event-driven writer.
#
# What IS assertable is that the artifact this function is the SOLE WRITER of is
# present, canonical and internally coherent -- a partial, truncated or
# half-written record fails these checks while a merely old one passes.
@register_probe("devops-recompute-governance", "devops-recompute-governance-gamma",
                declares=("GOVERNANCE_VERSION_TABLE",))
def _probe_governance_version_record(
    function_name: str, clients: Dict[str, object],
) -> Tuple[str, str]:
    ddb = clients.get("dynamodb")
    if ddb is None:
        return UNKNOWN, ("no dynamodb client supplied -- cannot read the governance-version "
                         "record this function is the sole writer of")
    lambda_client = clients.get("lambda")
    if lambda_client is None:
        return UNKNOWN, "no lambda client supplied -- cannot resolve GOVERNANCE_VERSION_TABLE"
    try:
        cfg = lambda_client.get_function_configuration(FunctionName=function_name)
        table = (((cfg or {}).get("Environment") or {}).get("Variables") or {}).get(
            "GOVERNANCE_VERSION_TABLE")
    except Exception as exc:  # noqa: BLE001
        return UNKNOWN, f"could not read GOVERNANCE_VERSION_TABLE from configuration: {_err(exc)}"
    if not table:
        return UNKNOWN, "GOVERNANCE_VERSION_TABLE is not set on this function"

    try:
        resp = ddb.get_item(
            TableName=table,
            Key={"version_id": {"S": _GOVERNANCE_VERSION_CANONICAL_KEY}},
        )
    except Exception as exc:  # noqa: BLE001
        return UNKNOWN, (f"could not read {_GOVERNANCE_VERSION_CANONICAL_KEY!r} from {table!r}: "
                         f"{_err(exc)} -- a read this probe cannot perform is unknown, not a pass")
    item = (resp or {}).get("Item")
    if not item:
        return FAIL, (f"{table!r} has no {_GOVERNANCE_VERSION_CANONICAL_KEY!r} item. This "
                      f"function is its SOLE WRITER (I28), so an absent canonical record means "
                      f"the governance-version contract is not being satisfied by anything.")

    def _s(key: str) -> str:
        return str((item.get(key) or {}).get("S") or "")

    def _n(key: str) -> str:
        return str((item.get(key) or {}).get("N") or "")

    problems: List[str] = []

    gov_hash = _s("governance_hash")
    if not _SHA256_HEX_RE.match(gov_hash):
        problems.append(f"governance_hash is not a 64-char lowercase hex digest "
                        f"(got {gov_hash[:24]!r}...)")

    for numeric in ("generation", "cas_version"):
        raw = _n(numeric)
        if not raw.isdigit() or int(raw) <= 0:
            problems.append(f"{numeric} is not a positive integer (got {raw!r})")

    files_raw = _s("files")
    try:
        files = json.loads(files_raw) if files_raw else []
    except Exception:  # noqa: BLE001
        files = None
        problems.append("files does not parse as JSON")
    if files is not None:
        if not isinstance(files, list) or not files:
            problems.append("files is empty or not a list -- the record claims to describe no "
                            "governance objects at all")
        else:
            for entry in files:
                if not isinstance(entry, dict) or not entry.get("s3_key"):
                    problems.append("a files[] entry is missing s3_key")
                    break
                if not _SHA256_HEX_RE.match(str(entry.get("checksum_sha256_hex") or "")):
                    problems.append(f"files[] entry {entry.get('s3_key')!r} has no valid "
                                    f"64-hex checksum_sha256_hex")
                    break

    # ENC-ISS-665 remedy 1, applied even though this probe reads no logs: state
    # written at or after this harness run started is state the run itself may
    # have caused, and is never accepted as evidence.
    updated_at = _s("updated_at")
    run_start_ms = clients.get("run_start_ms")
    if updated_at and isinstance(run_start_ms, (int, float)):
        try:
            written_ms = datetime.strptime(
                updated_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp() * 1000.0
        except Exception:  # noqa: BLE001
            problems.append(f"updated_at {updated_at!r} is not an ISO-8601 Z timestamp")
        else:
            if written_ms >= run_start_ms:
                return UNKNOWN, (
                    f"the canonical record's updated_at ({updated_at}) is at or after this "
                    f"harness run started -- refusing to accept as evidence a write this run "
                    f"may itself have triggered (ENC-ISS-665 remedy 1)")

    if problems:
        return FAIL, (f"the canonical governance-version record in {table!r} is present but "
                      f"INCOHERENT: {'; '.join(problems)}. This function is its sole writer, so "
                      f"a malformed record is this function's contract being violated, not a "
                      f"downstream's.")

    file_count = len(files or [])
    return PASS, (f"{table!r} holds a coherent {_GOVERNANCE_VERSION_CANONICAL_KEY!r} record: "
                  f"governance_hash {gov_hash[:12]}..., generation {_n('generation')}, "
                  f"cas_version {_n('cas_version')}, {file_count} governance object(s) each "
                  f"carrying an s3_key and a 64-hex checksum, updated_at {updated_at} "
                  f"(predating this run). Checked for STRUCTURAL COHERENCE rather than age: "
                  f"this writer is event-driven, so an old record on an unchanged governance "
                  f"corpus is correct behaviour, not staleness.")


def _enforce_no_pass_when_point3_failed(
    point4: PointResult, point3: Optional[PointResult],
) -> PointResult:
    """REMEDY 3 (ENC-TSK-P08/ENC-ISS-665, THE LOAD-BEARING ONE): point 4 must
    be structurally incapable of reporting PASS for a function whose point 3
    (live invocation) FAILED in this same run.

    This is deliberately an INDEPENDENT assertion: it does not look at logs,
    timestamps, streams, or anything _evaluate_schedule_window computed -- it
    only compares two already-finished verdicts. That means it holds even if
    remedies 1 (run-start anchoring), 2 (terminated-invocation requirement)
    and 4 (log-group-wide evaluation) were all absent or regressed, and even
    if a completely different (or completely broken) probe were registered in
    PROBE_REGISTRY tomorrow. Applied unconditionally by check_integration_edge
    -- there is no call path to point 4's public entry point that skips it.
    """
    if point3 is not None and point3.state == FAIL and point4.state == PASS:
        return PointResult(
            4, "integration_edge", FAIL,
            f"OVERRIDDEN: probe reported PASS ({point4.detail}), but point 3 (live_invocation) "
            f"FAILED in this same run ({point3.detail[:200]}) -- a function that just failed "
            f"live invocation cannot simultaneously have a healthy downstream integration edge. "
            f"This contradiction assertion is structurally independent of the freshness/"
            f"anchoring logic (ENC-ISS-665 remedy 3).",
            reason_code="point3_point4_contradiction",
        )
    return point4


def check_integration_edge(
    function_name: str, clients: Dict[str, object], *,
    point3_result: Optional[PointResult] = None,
) -> PointResult:
    # ENC-TSK-P19 / ENC-ISS-665: ownership is resolved BEFORE probe lookup.
    # A devops-owned function gets a declared NOT_APPLICABLE_ON_PLANE answer
    # rather than being probed by a plane that does not own it -- but the gate
    # still runs and still records a verdict, and remedy 3 below still applies
    # to whatever it produces. Nothing here short-circuits out of point 4.
    ownership = _resolve_devops_ownership(function_name)
    if ownership is not None:
        return _enforce_no_pass_when_point3_failed(ownership, point3_result)

    # ENC-ISS-678: attribution is checked BEFORE the probe runs. A probe pointed
    # at another function's artifact must never get the chance to return a
    # verdict -- remedy 3 below only catches a bad PASS when point 3 also
    # failed, so it cannot cover this case on its own.
    contract_failure = _verify_probe_contract(function_name, clients)
    if contract_failure is not None:
        reason_code, detail = contract_failure
        return _enforce_no_pass_when_point3_failed(
            PointResult(4, "integration_edge", UNKNOWN, detail, reason_code=reason_code),
            point3_result,
        )

    probe = PROBE_REGISTRY.get(function_name)
    if probe is None:
        result = PointResult(4, "integration_edge", UNKNOWN,
                              f"no integration probe registered for {function_name!r} -- "
                              f"function-level results say nothing about the downstream contract "
                              f"(BRD 8.4: function green is not system green). Register one in "
                              f"PROBE_REGISTRY to cover this function.",
                              reason_code="no_probe_registered")
    else:
        try:
            state, detail = probe(function_name, clients)
        except Exception as exc:  # noqa: BLE001
            result = PointResult(4, "integration_edge", UNKNOWN, f"probe raised: {_err(exc)}",
                                  reason_code="probe_error")
        else:
            if state not in _VALID_STATES:
                result = PointResult(4, "integration_edge", UNKNOWN,
                                      f"probe returned invalid state {state!r}",
                                      reason_code="probe_invalid_state")
            else:
                result = PointResult(4, "integration_edge", state, detail, reason_code="probe_result")
    # ENC-ISS-665 remedy 3 -- applied unconditionally, on every path above.
    return _enforce_no_pass_when_point3_failed(result, point3_result)


# ---------------------------------------------------------------------------
# Point 5 -- CI predicate observed failing
# ---------------------------------------------------------------------------

def check_ci_predicate_observed_failing(
    repo: str = DEFAULT_REPO, workflow: str = DEFAULT_CI_WORKFLOW, step_name: str = DEFAULT_CI_STEP,
    negative_control_test: str = DEFAULT_NEGATIVE_CONTROL_TEST, lookback: int = 50,
    run_pytest: Callable[..., "subprocess.CompletedProcess"] = subprocess.run,
    run_gh: Callable[..., "subprocess.CompletedProcess"] = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> PointResult:
    test_path = REPO_ROOT / negative_control_test
    if not test_path.is_file():
        return PointResult(5, "ci_predicate_observed_failing", FAIL,
                            f"no negative-control test file at {negative_control_test} -- "
                            f"a guard with no proof it can fail is not evidence (ENC-ISS-556)",
                            reason_code="negative_control_missing")

    try:
        proc = run_pytest(
            [sys.executable, "-m", "pytest", str(test_path), "-k", "negative or wrong_arch or empty", "-q"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=180,
        )
    except Exception as exc:  # noqa: BLE001
        return PointResult(5, "ci_predicate_observed_failing", UNKNOWN,
                            f"could not run negative-control test locally: {_err(exc)}",
                            reason_code="negative_control_check_error")

    if proc.returncode not in (0, 5):  # 5 = pytest "no tests collected" for the -k filter
        return PointResult(5, "ci_predicate_observed_failing", FAIL,
                            f"negative-control selection in {negative_control_test} does not currently pass "
                            f"(exit {proc.returncode}) -- the guard's ability to fail on bad input is not "
                            f"demonstrated: {proc.stdout[-300:]}",
                            reason_code="negative_control_failing")

    if which("gh") is None:
        return PointResult(5, "ci_predicate_observed_failing", UNKNOWN,
                            "gh CLI not available -- cannot confirm the guard has been observed red in real "
                            "CI history (the local negative-control test does pass)",
                            reason_code="gh_unavailable")

    try:
        proc = run_gh(
            ["gh", "run", "list", "--repo", repo, "--workflow", workflow, "--status", "failure",
             "--limit", str(lookback), "--json", "databaseId,conclusion,createdAt"],
            capture_output=True, text=True, timeout=30,
        )
    except Exception as exc:  # noqa: BLE001
        return PointResult(5, "ci_predicate_observed_failing", UNKNOWN, f"gh run list errored: {_err(exc)}",
                            reason_code="gh_query_error")

    if proc.returncode != 0:
        return PointResult(5, "ci_predicate_observed_failing", UNKNOWN,
                            f"gh run list failed: {proc.stderr.strip()[:300]}",
                            reason_code="gh_query_error")

    try:
        runs = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError as exc:
        return PointResult(5, "ci_predicate_observed_failing", UNKNOWN, f"could not parse gh output: {exc}",
                            reason_code="gh_output_unparseable")

    if not runs:
        return PointResult(5, "ci_predicate_observed_failing", UNKNOWN,
                            f"no failed runs of {workflow} found in the last {lookback} runs -- the guard "
                            f"exists and can fail locally, but has not been observed red in real CI within "
                            f"the lookback window (a gate never seen red is not proven, per ENC-ISS-556)",
                            reason_code="no_ci_history_found")

    for run in runs:
        rid = run.get("databaseId")
        try:
            log_proc = run_gh(["gh", "run", "view", str(rid), "--repo", repo, "--log-failed"],
                               capture_output=True, text=True, timeout=60)
        except Exception as exc:  # noqa: BLE001
            continue
        if log_proc.returncode == 0 and step_name in log_proc.stdout:
            return PointResult(5, "ci_predicate_observed_failing", PASS,
                                f"negative-control passes locally AND run {rid} shows '{step_name}' "
                                f"failing in real CI history",
                                reason_code="ci_history_confirmed_red")

    return PointResult(5, "ci_predicate_observed_failing", UNKNOWN,
                        f"found {len(runs)} failed {workflow} run(s) in the last {lookback}, but none had a "
                        f"failing '{step_name}' step in the fetched logs -- those runs may have failed for "
                        f"an unrelated step",
                        reason_code="ci_history_inconclusive")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

ARTIFACT_TAG_SCHEME_WARNING = (
    "artifact_tag_scheme_divergence: _build.yml writes DOTTED S3 keys "
    "(e.g. 'arm64-py3.12'); tools/verify_lambda_arch_parity.py's ARTIFACT_ARCH_TAGS "
    "expects UNDOTTED keys (e.g. 'arm64-py312'). This harness resolves against the "
    "DOTTED scheme because that is what is live in s3://jreese-net/lambda-artifacts/ "
    "today (confirmed 2026-08-23). Reconciling verify_lambda_arch_parity.py is owned "
    "by ENC-TSK-O82 and is out of scope here."
)


def evaluate_function(
    *, lambda_client, s3_client, logs_client, function_name: str,
    apigw_client=None, ddb_client=None,
    expected_arch: str = "arm64", py_version: str = "3.12",
    commit_sha: Optional[str] = None, bucket: str = ARTIFACT_BUCKET_DEFAULT,
    key_prefix: str = ARTIFACT_KEY_PREFIX_DEFAULT, invoke_payload: str = "{}",
    env: str = "v4-gamma",
    repo: str = DEFAULT_REPO, ci_workflow: str = DEFAULT_CI_WORKFLOW,
    ci_step: str = DEFAULT_CI_STEP, negative_control_test: str = DEFAULT_NEGATIVE_CONTROL_TEST,
    ci_lookback: int = 50,
    run_start_ms: Optional[float] = None,
) -> FunctionReport:
    # ENC-ISS-665 remedy 1: capture (or accept an injected) run-start anchor
    # BEFORE point 3 runs, so point 4 can never treat point 3's own
    # invocation -- or anything else this run causes -- as evidence of
    # "freshness." See _evaluate_schedule_window.
    if run_start_ms is None:
        run_start_ms = time.time() * 1000.0

    point1 = check_artifact_identity(lambda_client, s3_client, function_name, expected_arch,
                                      py_version, commit_sha, bucket, key_prefix, env=env)
    point2 = check_layer_coherence(lambda_client, function_name)
    point3 = check_live_invocation(lambda_client, function_name, invoke_payload)
    point4 = check_integration_edge(
        function_name,
        # ENC-TSK-P19: point 4's probes read downstream state that function
        # configuration cannot express -- S3 for "did the mart produce a mart",
        # apigatewayv2 for "is the authorizer on BOTH decision routes". A None
        # client makes the relevant probe report UNKNOWN and say so; it never
        # makes it pass.
        {"lambda": lambda_client, "logs": logs_client, "s3": s3_client,
         "apigatewayv2": apigw_client, "dynamodb": ddb_client,
         "run_start_ms": run_start_ms},
        # ENC-ISS-665 remedy 3 (load-bearing): point 4 is structurally
        # incapable of returning PASS when point 3 FAILED in this same run.
        point3_result=point3,
    )
    point5 = check_ci_predicate_observed_failing(repo, ci_workflow, ci_step, negative_control_test, ci_lookback)

    points = [point1, point2, point3, point4, point5]
    return FunctionReport(function_name=function_name, points=points, warnings=[ARTIFACT_TAG_SCHEME_WARNING])


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--function-name", action="append", default=[],
                   help="Lambda function name to validate. Repeatable.")
    p.add_argument("--arch", default="arm64")
    p.add_argument("--py-version", default="3.12")
    p.add_argument("--commit-sha", default=None,
                   help="Expected deployed commit sha (40-hex) for point 1. Without it, point 1 is unknown.")
    p.add_argument("--bucket", default=ARTIFACT_BUCKET_DEFAULT)
    p.add_argument("--key-prefix", default=ARTIFACT_KEY_PREFIX_DEFAULT)
    p.add_argument("--env", default="v4-gamma",
                   help="Environment manifest under envs/ whose function_name_map maps the "
                        "deployed function name back to the artifact's source-directory "
                        "basename (ENC-TSK-P06).")
    p.add_argument("--invoke-payload", default="{}")
    p.add_argument("--profile", default=None)
    p.add_argument("--region", default="us-west-2")
    p.add_argument("--repo", default=DEFAULT_REPO)
    p.add_argument("--ci-workflow", default=DEFAULT_CI_WORKFLOW)
    p.add_argument("--ci-step", default=DEFAULT_CI_STEP)
    p.add_argument("--negative-control-test", default=DEFAULT_NEGATIVE_CONTROL_TEST)
    p.add_argument("--ci-lookback", type=int, default=50)
    p.add_argument("--output", default=None, help="Also write the JSON report to this path.")
    p.add_argument("--self-test", action="store_true",
                   help="Run this harness's own pytest self-tests (no AWS calls) and exit with their result.")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.self_test:
        test_file = TOOLS_DIR / "test_verify_arm64_validation_harness.py"
        proc = subprocess.run([sys.executable, "-m", "pytest", str(test_file), "-v"])
        return proc.returncode

    if not args.function_name:
        parser.error("at least one --function-name is required (or use --self-test)")

    try:
        import boto3  # noqa: PLC0415 - optional dependency, only needed for live runs
    except ImportError:
        print(json.dumps({"error": "boto3 not available"}), file=sys.stderr)
        return 2

    session_kwargs = {}
    if args.profile:
        session_kwargs["profile_name"] = args.profile
    session = boto3.Session(**session_kwargs)
    lambda_client = session.client("lambda", region_name=args.region)
    s3_client = session.client("s3", region_name=args.region)
    logs_client = session.client("logs", region_name=args.region)
    try:
        apigw_client = session.client("apigatewayv2", region_name=args.region)
    except Exception:  # noqa: BLE001 - probe reports UNKNOWN rather than failing the run
        apigw_client = None
    try:
        ddb_client = session.client("dynamodb", region_name=args.region)
    except Exception:  # noqa: BLE001 - probe reports UNKNOWN rather than failing the run
        ddb_client = None

    reports = [
        evaluate_function(
            lambda_client=lambda_client, s3_client=s3_client, logs_client=logs_client,
            apigw_client=apigw_client, ddb_client=ddb_client,
            function_name=fn, expected_arch=args.arch, py_version=args.py_version,
            commit_sha=args.commit_sha, bucket=args.bucket, key_prefix=args.key_prefix,
            invoke_payload=args.invoke_payload, env=args.env,
            repo=args.repo, ci_workflow=args.ci_workflow,
            ci_step=args.ci_step, negative_control_test=args.negative_control_test,
            ci_lookback=args.ci_lookback,
        )
        for fn in args.function_name
    ]

    out = {
        "generated_at": _now(),
        "artifact_tag_scheme_resolved": f"{args.arch}-py{args.py_version} (dotted)",
        "reason_code_glossary": REASON_CODE_GLOSSARY,
        "functions": [r.to_dict() for r in reports],
    }
    text = json.dumps(out, indent=2, default=str)
    print(text)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")

    return 1 if any(r.overall != PASS for r in reports) else 0


if __name__ == "__main__":
    sys.exit(main())
