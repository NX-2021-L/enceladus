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
                           not merely Architectures==['arm64'].
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

At the function level: overall = FAIL if any point is FAIL; else UNKNOWN if
any point is UNKNOWN; else PASS. UNKNOWN is non-passing.

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
    DENIED (explicit deny in enceladus-agent-cli-policy, confirmed live).
    Point 1's artifact-vs-S3 comparison reports UNKNOWN under this profile
    for the same reason. A CI OIDC role or broader-scoped credential can
    complete both checks; this file does not assume it has one.
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
    "artifact_missing": "the expected artifact object does not exist at the resolved S3 key",
    "permission_denied": "the calling identity is explicitly denied the AWS action needed to complete this check",
    "s3_read_error": "an S3 error occurred that is not a permission denial or a missing key",
    "digest_match": "recomputed artifact digest matches the deployed CodeSha256",
    "digest_mismatch": "recomputed artifact digest does not match the deployed CodeSha256",
    # point 2 -- layer_coherence
    "zero_layers": "the function declares no layers at all -- vacuously coherent",
    "layer_contents_verified": "every attached layer's real content was downloaded and inspected (pure-Python or arch-matched compiled objects)",
    "compiled_object_mismatch": "a layer's compiled object does not match the function's actual architecture",
    "layer_arn_unparseable": "a layer ARN could not be parsed into name/version",
    "layer_not_found": "GetLayerVersion could not find the layer version (commonly a cross-account AWS-managed layer that cannot be introspected from this account)",
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
    "probe_error": "the registered probe raised an exception",
    "probe_invalid_state": "the registered probe returned a state outside pass/fail/unknown",
    "probe_result": "the registered probe ran to completion and returned this state",
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

    def __post_init__(self) -> None:
        if self.state not in _VALID_STATES:
            raise ValueError(f"invalid state {self.state!r}; must be one of {_VALID_STATES}")
        if self.reason_code not in REASON_CODES:
            raise ValueError(f"invalid reason_code {self.reason_code!r}; must be one of {sorted(REASON_CODES)}")

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
        states = {p.state for p in self.points}
        if FAIL in states:
            return FAIL
        if UNKNOWN in states:
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

    def to_dict(self) -> dict:
        return {
            "function_name": self.function_name,
            "overall": self.overall,
            "generated_at": self.generated_at,
            "points": [p.to_dict() for p in self.points],
            "permission_denied_points": self.permission_denied_points,
            "warnings": self.warnings,
        }


# ---------------------------------------------------------------------------
# Point 1 -- artifact identity
# ---------------------------------------------------------------------------

def _artifact_key(function_name: str, expected_arch: str, py_version: str, commit_sha: str,
                   key_prefix: str = ARTIFACT_KEY_PREFIX_DEFAULT) -> str:
    # DOTTED scheme -- see module docstring "ARTIFACT TAG SCHEME".
    return f"{key_prefix}/{expected_arch}-py{py_version}/{function_name}-{commit_sha}.zip"


def check_artifact_identity(
    lambda_client, s3_client, function_name: str, expected_arch: str, py_version: str,
    commit_sha: Optional[str], bucket: str = ARTIFACT_BUCKET_DEFAULT,
    key_prefix: str = ARTIFACT_KEY_PREFIX_DEFAULT,
) -> PointResult:
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
        return PointResult(1, "artifact_identity", UNKNOWN,
                            "no --commit-sha supplied; cannot resolve the expected S3 artifact key "
                            "without knowing which commit was meant to be deployed",
                            reason_code="no_commit_sha")

    key = _artifact_key(function_name, expected_arch, py_version, commit_sha, key_prefix)
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
            return PointResult(1, "artifact_identity", UNKNOWN,
                                f"S3 GetObject denied for s3://{bucket}/{key} under the calling identity "
                                f"(confirmed live: enceladus-agent-cli is explicitly denied s3:GetObject "
                                f"on this bucket) -- point 1 needs a broader-scoped read role (e.g. the "
                                f"CI OIDC role) to complete under this credential",
                                reason_code="permission_denied")
        return PointResult(1, "artifact_identity", UNKNOWN, f"S3 read error for {key}: {msg}",
                            reason_code="s3_read_error")

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

def _inspect_one_layer(lambda_client, layer_arn: str, function_arch: str,
                        downloader: Callable[[str], bytes],
                        classify_so: Callable[[Path], Optional[str]]) -> Tuple[str, str, str]:
    """Returns (state, reason_code, note) for one attached layer."""
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
            so_files = list((tmp_path / "content").rglob("*.so")) + list((tmp_path / "content").rglob("*.so.*"))
            if not so_files:
                return PASS, "layer_contents_verified", (
                    f"{layer_arn}: zero .so files -- genuinely architecture-neutral "
                    f"(CompatibleArchitectures metadata={compat_meta}, not relied on)")

            mismatches, unknowns = [], []
            for so in so_files:
                arch = classify_so(so)
                if arch is None:
                    unknowns.append(so.name)
                elif arch != function_arch:
                    mismatches.append(f"{so.name}={arch}")

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
                f"{layer_arn}: {len(so_files)} compiled object(s), all match function arch "
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
        state, reason, note = _inspect_one_layer(lambda_client, arn, actual_arch, downloader, classify_so)
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
# ---------------------------------------------------------------------------

# A probe receives (function_name, clients) where clients is a dict of
# already-constructed boto3 clients (e.g. {"logs": ..., "lambda": ...}), and
# must return (state, detail) with state in PASS/FAIL/UNKNOWN. Never PASS
# by default -- a missing probe is UNKNOWN, not a pass (BRD 8.4: function
# green is not system green).
IntegrationProbe = Callable[[str, Dict[str, object]], Tuple[str, str]]
PROBE_REGISTRY: Dict[str, IntegrationProbe] = {}


def register_probe(*function_names: str) -> Callable[[IntegrationProbe], IntegrationProbe]:
    def deco(fn: IntegrationProbe) -> IntegrationProbe:
        for name in function_names:
            PROBE_REGISTRY[name] = fn
        return fn
    return deco


@register_probe("devops-recompute-governance", "devops-recompute-governance-gamma",
                "devops-governance-mart", "devops-governance-mart-gamma")
def _probe_governance_mart_schedule(function_name: str, clients: Dict[str, object],
                                     max_age_hours: float = 26.0) -> Tuple[str, str]:
    """Demonstration probe for BRD 8.4's own example: 'the mart must produce a
    mart on its schedule.' Checks CloudWatch Logs for a recent invocation
    (within the schedule window) whose latest events contain no
    ERROR/Traceback lines. This is the DVP-ISS-103 class of failure: a
    scheduled job can stop firing entirely and be invisible to every
    function-level check that only asks 'does invoke succeed.'
    """
    logs_client = clients.get("logs")
    if logs_client is None:
        return UNKNOWN, "no logs client provided to probe"
    log_group = f"/aws/lambda/{function_name}"
    try:
        streams = logs_client.describe_log_streams(
            logGroupName=log_group, orderBy="LastEventTime", descending=True, limit=1,
        ).get("logStreams", [])
    except Exception as exc:  # noqa: BLE001
        return UNKNOWN, f"could not read {log_group}: {_err(exc)}"

    if not streams:
        return UNKNOWN, f"{log_group} has no log streams -- cannot tell whether it has ever run"

    last_event_ms = streams[0].get("lastEventTimestamp")
    if last_event_ms is None:
        return UNKNOWN, f"{log_group} latest stream has no lastEventTimestamp"

    age_hours = (time.time() * 1000 - last_event_ms) / 3_600_000.0
    if age_hours > max_age_hours:
        return FAIL, (f"{log_group} last wrote {age_hours:.1f}h ago (> {max_age_hours}h schedule window) "
                       f"-- DVP-ISS-103 class: a stopped cron is silent without this check")

    try:
        events = logs_client.get_log_events(
            logGroupName=log_group, logStreamName=streams[0]["logStreamName"],
            limit=50, startFromHead=False,
        ).get("events", [])
    except Exception as exc:  # noqa: BLE001
        return UNKNOWN, f"could not read events for {log_group}: {_err(exc)}"

    if not events:
        return UNKNOWN, f"{log_group} latest stream is empty"

    bad = [e["message"] for e in events if "ERROR" in e.get("message", "") or "Traceback" in e.get("message", "")]
    if bad:
        return FAIL, f"{log_group} latest run contains {len(bad)} error line(s): {bad[0][:200]}"
    return PASS, f"{log_group} last wrote {age_hours:.1f}h ago with no ERROR/Traceback in latest {len(events)} events"


def check_integration_edge(function_name: str, clients: Dict[str, object]) -> PointResult:
    probe = PROBE_REGISTRY.get(function_name)
    if probe is None:
        return PointResult(4, "integration_edge", UNKNOWN,
                            f"no integration probe registered for {function_name!r} -- "
                            f"function-level results say nothing about the downstream contract "
                            f"(BRD 8.4: function green is not system green). Register one in "
                            f"PROBE_REGISTRY to cover this function.",
                            reason_code="no_probe_registered")
    try:
        state, detail = probe(function_name, clients)
    except Exception as exc:  # noqa: BLE001
        return PointResult(4, "integration_edge", UNKNOWN, f"probe raised: {_err(exc)}",
                            reason_code="probe_error")
    if state not in _VALID_STATES:
        return PointResult(4, "integration_edge", UNKNOWN, f"probe returned invalid state {state!r}",
                            reason_code="probe_invalid_state")
    return PointResult(4, "integration_edge", state, detail, reason_code="probe_result")


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
    expected_arch: str = "arm64", py_version: str = "3.12",
    commit_sha: Optional[str] = None, bucket: str = ARTIFACT_BUCKET_DEFAULT,
    key_prefix: str = ARTIFACT_KEY_PREFIX_DEFAULT, invoke_payload: str = "{}",
    repo: str = DEFAULT_REPO, ci_workflow: str = DEFAULT_CI_WORKFLOW,
    ci_step: str = DEFAULT_CI_STEP, negative_control_test: str = DEFAULT_NEGATIVE_CONTROL_TEST,
    ci_lookback: int = 50,
) -> FunctionReport:
    points = [
        check_artifact_identity(lambda_client, s3_client, function_name, expected_arch,
                                 py_version, commit_sha, bucket, key_prefix),
        check_layer_coherence(lambda_client, function_name),
        check_live_invocation(lambda_client, function_name, invoke_payload),
        check_integration_edge(function_name, {"lambda": lambda_client, "logs": logs_client}),
        check_ci_predicate_observed_failing(repo, ci_workflow, ci_step, negative_control_test, ci_lookback),
    ]
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

    reports = [
        evaluate_function(
            lambda_client=lambda_client, s3_client=s3_client, logs_client=logs_client,
            function_name=fn, expected_arch=args.arch, py_version=args.py_version,
            commit_sha=args.commit_sha, bucket=args.bucket, key_prefix=args.key_prefix,
            invoke_payload=args.invoke_payload, repo=args.repo, ci_workflow=args.ci_workflow,
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
