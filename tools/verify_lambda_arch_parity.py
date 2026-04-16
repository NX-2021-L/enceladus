#!/usr/bin/env python3
"""Verify Lambda architecture parity between CFN and deploy scripts.

CI guard preventing arm64 architecture from reaching production.
Validates that:
  1. Every Lambda in 02-compute.yaml uses !If [IsGamma, arm64, x86_64]
     for Architectures (prod must resolve to x86_64).
  2. Every Lambda uses !If [IsGamma, python3.12, python3.11] for Runtime
     (prod must resolve to python3.11).
  3. Deploy scripts with pip --platform use ENVIRONMENT_SUFFIX conditionals
     that default to x86_64/py3.11 for production (empty suffix).

Part of ENC-PLN-019 (V3 Full Restoration & Production Lockdown).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import List, NamedTuple, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPUTE_TEMPLATE = REPO_ROOT / "infrastructure/cloudformation/02-compute.yaml"
MANIFEST_PATH = REPO_ROOT / "infrastructure/lambda_workflow_manifest.json"
SHARED_LAYER_DEPLOY = REPO_ROOT / "backend/lambda/shared_layer/deploy.sh"

# Expected CFN conditional patterns for prod safety
EXPECTED_ARCH_PATTERN = re.compile(
    r"^\s*-\s*!If\s+\[IsGamma,\s*arm64,\s*x86_64\]\s*$"
)
EXPECTED_RUNTIME_PATTERN = re.compile(
    r"^\s*Runtime:\s*!If\s+\[IsGamma,\s*python3\.12,\s*python3\.11\]\s*$"
)

# Patterns that indicate a hardcoded (non-conditional) architecture or runtime
# Handles both inline [arm64] and YAML list "- arm64" forms
HARDCODED_ARCH_INLINE = re.compile(r"^\s*Architectures:\s*\[(arm64|x86_64)\]\s*$")
HARDCODED_ARCH_LIST = re.compile(r"^\s*-\s*(arm64|x86_64)\s*$")
HARDCODED_RUNTIME = re.compile(r"^\s*Runtime:\s*(python3\.\d+)\s*$")

# Deploy script patterns
DEPLOY_PROD_X86 = re.compile(
    r'pip_platform="manylinux2014_x86_64".*pip_pyver="3\.11"'
)
DEPLOY_GAMMA_ARM = re.compile(
    r'pip_platform="manylinux2014_aarch64".*pip_pyver="3\.12"'
)
DEPLOY_ENV_CONDITIONAL = re.compile(
    r'if\s+\[\s+-n\s+"\$\{ENVIRONMENT_SUFFIX:-\}"\s+\]'
)

# ENC-TSK-E19: block inserted into every deploy.sh to invoke
# tools/verify_lambda_package_arch.py. The block necessarily mentions both
# "arm64" and "x86_64" (one is selected by ENVIRONMENT_SUFFIX at runtime).
# Stripped from deploy-script content before the arch-literal scans below so
# the verifier injection does not cause has_aarch64 to fire on x86_64-only
# scripts (e.g. project_service/deploy.sh, github_integration/deploy.sh).
_ENC_TSK_E19_BLOCK_RE = re.compile(
    r'^[ \t]*# ENC-TSK-E19:.*?'
    r'^[ \t]*--expected-arch "\$\{E19_EXPECTED_ARCH\}"\s*$',
    re.MULTILINE | re.DOTALL,
)


class LambdaBlock(NamedTuple):
    """A Lambda function block parsed from the CFN template."""
    resource_name: str
    function_name: str
    line_number: int
    runtime_line: str
    runtime_lineno: int
    arch_line: str
    arch_lineno: int


def _parse_lambda_blocks(template_path: Path) -> List[LambdaBlock]:
    """Parse Lambda function blocks from the CFN template."""
    lines = template_path.read_text(encoding="utf-8").splitlines()
    blocks: List[LambdaBlock] = []

    i = 0
    while i < len(lines):
        line = lines[i].rstrip()

        # Find resource blocks that are Lambda functions
        if line.strip().startswith("Type:") and "AWS::Lambda::Function" in line:
            # Walk back to find the resource name
            resource_name = ""
            for j in range(i - 1, max(i - 10, -1), -1):
                candidate = lines[j].rstrip()
                if candidate and not candidate.startswith(" ") and not candidate.startswith("#"):
                    break
                if re.match(r"^  \w+.*:$", candidate):
                    resource_name = candidate.strip().rstrip(":")
                    break

            # Find FunctionName, Runtime, and Architectures within this block
            function_name = ""
            runtime_line = ""
            runtime_lineno = 0
            arch_line = ""
            arch_lineno = 0

            for k in range(i + 1, min(i + 40, len(lines))):
                l = lines[k].rstrip()

                if l.strip().startswith("FunctionName:"):
                    fn_val = l.split("FunctionName:", 1)[1].strip()
                    # Handle !Sub patterns
                    sub_match = re.match(r"""!Sub\s+['"]([^'"]+)['"]""", fn_val)
                    if sub_match:
                        function_name = sub_match.group(1).replace(
                            "${EnvironmentSuffix}", ""
                        )
                    else:
                        function_name = fn_val.strip("'\"")

                if l.strip().startswith("Runtime:"):
                    runtime_line = l
                    runtime_lineno = k + 1  # 1-based

                if l.strip().startswith("Architectures:"):
                    # The value might be on the same line or the next line
                    if "[" in l:
                        arch_line = l
                        arch_lineno = k + 1
                    elif k + 1 < len(lines):
                        arch_line = lines[k + 1]
                        arch_lineno = k + 2

                # Stop at the next resource block
                if k > i + 2 and re.match(r"^  \w+.*:", l) and not l.startswith("    "):
                    break

            if function_name and runtime_line:
                blocks.append(LambdaBlock(
                    resource_name=resource_name,
                    function_name=function_name,
                    line_number=i + 1,
                    runtime_line=runtime_line,
                    runtime_lineno=runtime_lineno,
                    arch_line=arch_line,
                    arch_lineno=arch_lineno,
                ))
        i += 1

    return blocks


def _validate_cfn(blocks: List[LambdaBlock]) -> List[str]:
    """Validate that all CFN Lambda declarations use IsGamma conditionals."""
    errors: List[str] = []

    for block in blocks:
        # Check Runtime
        if not EXPECTED_RUNTIME_PATTERN.match(block.runtime_line):
            match = HARDCODED_RUNTIME.match(block.runtime_line.strip())
            if match:
                runtime_val = match.group(1)
                errors.append(
                    f"{block.function_name} (line {block.runtime_lineno}): "
                    f"hardcoded Runtime={runtime_val}, expected "
                    f"!If [IsGamma, python3.12, python3.11]"
                )
            else:
                errors.append(
                    f"{block.function_name} (line {block.runtime_lineno}): "
                    f"unexpected Runtime pattern: {block.runtime_line.strip()}"
                )

        # Check Architectures
        if not EXPECTED_ARCH_PATTERN.match(block.arch_line):
            inline_match = HARDCODED_ARCH_INLINE.match(block.arch_line.strip())
            list_match = HARDCODED_ARCH_LIST.match(block.arch_line)
            if inline_match:
                arch_val = inline_match.group(1)
                errors.append(
                    f"{block.function_name} (line {block.arch_lineno}): "
                    f"hardcoded Architectures=[{arch_val}], expected "
                    f"!If [IsGamma, arm64, x86_64]"
                )
            elif list_match:
                arch_val = list_match.group(1)
                errors.append(
                    f"{block.function_name} (line {block.arch_lineno}): "
                    f"hardcoded Architectures=[{arch_val}], expected "
                    f"!If [IsGamma, arm64, x86_64]"
                )
            else:
                errors.append(
                    f"{block.function_name} (line {block.arch_lineno}): "
                    f"unexpected Architectures pattern: {block.arch_line.strip()}"
                )

    return errors


def _validate_deploy_scripts() -> List[str]:
    """Validate deploy scripts don't produce arm64 builds for production.

    Three valid patterns:
    1. Hardcoded x86_64 only — always safe (most API Lambdas)
    2. ENVIRONMENT_SUFFIX conditional — x86_64 for prod, arm64 for gamma
    3. No --platform flag — no binary deps, safe
    """
    errors: List[str] = []

    import json
    if not MANIFEST_PATH.is_file():
        return ["Lambda workflow manifest not found"]

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    for entry in manifest.get("functions", []):
        deploy_script = entry.get("deploy_script")
        if not deploy_script:
            continue

        script_path = REPO_ROOT / deploy_script
        if not script_path.is_file():
            continue

        content = script_path.read_text(encoding="utf-8")
        fn_name = entry.get("function_name", deploy_script)

        # Scripts without --platform are safe (no binary deps)
        if "--platform" not in content:
            continue

        # ENC-TSK-E19: strip the package-arch verifier injection before running
        # the arch-literal scan. The injection necessarily mentions both "arm64"
        # and "x86_64" (it chooses one via ENVIRONMENT_SUFFIX at runtime), which
        # would otherwise trip the has_aarch64 / DEPLOY_PROD_X86 rules on scripts
        # that are otherwise x86_64-only in their build logic.
        scan_content = _ENC_TSK_E19_BLOCK_RE.sub("", content)

        has_aarch64 = "aarch64" in scan_content or "arm64" in scan_content
        has_x86 = "x86_64" in scan_content

        # If script references arm64/aarch64, it MUST use conditional gating
        if has_aarch64:
            if not DEPLOY_ENV_CONDITIONAL.search(scan_content):
                errors.append(
                    f"{fn_name} ({deploy_script}): references arm64/aarch64 "
                    f"without ENVIRONMENT_SUFFIX conditional guard"
                )
                continue

            # Prod path must use x86_64/py3.11
            if not DEPLOY_PROD_X86.search(scan_content):
                errors.append(
                    f"{fn_name} ({deploy_script}): production path must use "
                    f"manylinux2014_x86_64 with py3.11"
                )

            # Gamma path must use arm64/py3.12
            if not DEPLOY_GAMMA_ARM.search(scan_content):
                errors.append(
                    f"{fn_name} ({deploy_script}): gamma path must use "
                    f"manylinux2014_aarch64 with py3.12"
                )
        elif has_x86:
            # Hardcoded x86_64 only — safe for production
            pass
        else:
            errors.append(
                f"{fn_name} ({deploy_script}): uses --platform but "
                f"platform target is unrecognized"
            )

    return errors


def _validate_shared_layer_deploy_script() -> List[str]:
    """Validate that shared_layer/deploy.sh targets the consumer's full ABI.

    ENC-ISS-198 / ENC-TSK-D22: enceladus-shared:7 was published 2026-04-03 by
    ENC-TSK-B42 with a python3.12-tagged cffi backend that prod (python3.11)
    cannot load. The build script had only ``--platform`` to override OS/arch
    but not ``--python-version``/``--abi`` to override the Python ABI tag.
    Result: pip downloaded cp312 wheels on the python3.12 builder host and the
    layer was silently broken on every prod Lambda using ``import jwt``.

    This check enforces that shared_layer/deploy.sh has all three pip flags
    AND that the prod and gamma paths target the right combinations.

    Required prod targeting (ENVIRONMENT_SUFFIX empty):
        --platform manylinux2014_x86_64
        --python-version 3.11
        --abi cp311

    Required gamma targeting (ENVIRONMENT_SUFFIX=-gamma):
        --platform manylinux2014_aarch64
        --python-version 3.12
        --abi cp312

    The script must also pass --compatible-architectures explicitly to
    aws lambda publish-layer-version so the published layer's compatibility
    metadata is honest and the V3 production lock can audit it.
    """
    errors: List[str] = []

    if not SHARED_LAYER_DEPLOY.is_file():
        return [f"Shared layer deploy script missing: {SHARED_LAYER_DEPLOY}"]

    content = SHARED_LAYER_DEPLOY.read_text(encoding="utf-8")

    # Must pass all three pip flags (prefix with -- so substring match isn't fooled by comments)
    required_flags = (
        "--platform",
        "--python-version",
        "--abi",
    )
    for flag in required_flags:
        if flag not in content:
            errors.append(
                f"shared_layer/deploy.sh: missing required pip flag '{flag}'. "
                f"All three of --platform, --python-version, --abi must be present "
                f"to override the consumer ABI (ENC-ISS-198 / ENC-TSK-D22)."
            )

    # Prod-path targeting must be present (either via conditional or hardcoded)
    has_prod_platform = "manylinux2014_x86_64" in content
    has_prod_pyver = '"3.11"' in content or "'3.11'" in content
    has_prod_abi = "cp311" in content
    if not (has_prod_platform and has_prod_pyver and has_prod_abi):
        errors.append(
            "shared_layer/deploy.sh: prod build target incomplete. Required values "
            "manylinux2014_x86_64 / 3.11 / cp311 must all be present "
            "(found platform=%s, pyver=%s, abi=%s)"
            % (has_prod_platform, has_prod_pyver, has_prod_abi)
        )

    # publish-layer-version must declare --compatible-architectures explicitly
    # so the V3 production lock can audit the metadata
    if "--compatible-architectures" not in content:
        errors.append(
            "shared_layer/deploy.sh: aws lambda publish-layer-version must pass "
            "--compatible-architectures so the layer metadata is honest and the "
            "V3 production lock can audit it (ENC-ISS-198)."
        )

    # The legacy comment block referencing only ENC-ISS-041 is insufficient.
    # The new comment must reference ENC-ISS-198 to surface the third recurrence.
    if "ENC-ISS-198" not in content:
        errors.append(
            "shared_layer/deploy.sh: must reference ENC-ISS-198 in the build "
            "script's documentation comment to surface the three-flags requirement "
            "(historical precedents: ENC-ISS-041, ENC-ISS-044, ENC-ISS-198)."
        )

    if not errors:
        print(
            "[INFO] shared_layer/deploy.sh validated: all three pip flags "
            "present (--platform, --python-version, --abi), prod build target "
            "manylinux2014_x86_64/3.11/cp311 confirmed"
        )

    return errors


def _validate_manifest_expectations() -> List[str]:
    """Cross-validate manifest expected_architecture/expected_runtime against CFN and deploy scripts.

    The manifest serves as the single source of truth for what each environment should use.
    This check ensures the manifest expectations are internally consistent and that the
    CFN template's IsGamma conditionals resolve to the manifest's declared values.

    Part of ENC-PLN-020 (Production Deploy Hardening) / ENC-TSK-D17 AC7.
    """
    errors: List[str] = []

    import json
    if not MANIFEST_PATH.is_file():
        return []  # Manifest not required for basic parity check

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    expected_arch = manifest.get("expected_architecture", {})
    expected_runtime = manifest.get("expected_runtime", {})

    if not expected_arch or not expected_runtime:
        return []  # No manifest expectations defined yet — skip

    # Validate manifest expectations match the IsGamma conditional contract
    # The CFN pattern is: !If [IsGamma, <gamma_value>, <prod_value>]
    # So prod=x86_64 and gamma=arm64 must match manifest
    if expected_arch.get("prod") != "x86_64":
        errors.append(
            f"Manifest expected_architecture.prod={expected_arch.get('prod')}, "
            f"but CFN IsGamma resolves prod to x86_64"
        )
    if expected_arch.get("gamma") != "arm64":
        errors.append(
            f"Manifest expected_architecture.gamma={expected_arch.get('gamma')}, "
            f"but CFN IsGamma resolves gamma to arm64"
        )
    if expected_runtime.get("prod") != "python3.11":
        errors.append(
            f"Manifest expected_runtime.prod={expected_runtime.get('prod')}, "
            f"but CFN IsGamma resolves prod to python3.11"
        )
    if expected_runtime.get("gamma") != "python3.12":
        errors.append(
            f"Manifest expected_runtime.gamma={expected_runtime.get('gamma')}, "
            f"but CFN IsGamma resolves gamma to python3.12"
        )

    if not errors:
        print(
            f"[INFO] Manifest expectations cross-validated: "
            f"prod={expected_arch.get('prod')}/{expected_runtime.get('prod')}, "
            f"gamma={expected_arch.get('gamma')}/{expected_runtime.get('gamma')}"
        )

    return errors


# ENC-TSK-E29: S3 artifact layout validation (E20 AC-5)
ARTIFACT_ARCH_TAGS = {
    "prod": "x86_64-py311",
    "gamma": "arm64-py312",
}
ARTIFACT_BUCKET = "jreese-net"


def _validate_artifact_s3_layout(
    git_sha: str,
    bucket: str = ARTIFACT_BUCKET,
    environments: Optional[List[str]] = None,
) -> List[str]:
    """Check S3 bucket for correct arch-tagged artifact structure per manifest function.

    For each function in the manifest, verifies that a zip artifact exists at
    the expected S3 key for each target environment:
      lambda-artifacts/{git_sha}/x86_64-py311/{function_name}.zip  (prod)
      lambda-artifacts/{git_sha}/arm64-py312/{function_name}.zip   (gamma)

    Returns a list of error strings for missing or misplaced artifacts.
    Requires boto3 and AWS credentials with S3 read access.
    """
    import json

    try:
        import boto3
    except ImportError:
        return ["boto3 not available — cannot validate S3 artifact layout"]

    if not MANIFEST_PATH.is_file():
        return ["Lambda workflow manifest not found — cannot validate S3 artifacts"]

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    functions = manifest.get("functions", [])
    if not functions:
        return ["No functions in manifest — nothing to validate"]

    if environments is None:
        environments = ["prod", "gamma"]

    errors: List[str] = []
    s3 = boto3.client("s3", region_name="us-west-2")

    for env in environments:
        arch_tag = ARTIFACT_ARCH_TAGS.get(env)
        if not arch_tag:
            errors.append(f"Unknown environment '{env}' — expected 'prod' or 'gamma'")
            continue

        prefix = f"lambda-artifacts/{git_sha}/{arch_tag}/"

        # List all objects under this prefix once
        try:
            resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
        except Exception as exc:
            errors.append(f"S3 list failed for {env} prefix {prefix}: {exc}")
            continue

        existing_keys = {
            obj["Key"] for obj in resp.get("Contents", [])
        }

        for entry in functions:
            fn_name = entry.get("function_name", "")
            if not fn_name:
                continue
            expected_key = f"{prefix}{fn_name}.zip"
            if expected_key not in existing_keys:
                errors.append(
                    f"{fn_name} ({env}): missing artifact at "
                    f"s3://{bucket}/{expected_key}"
                )

    if not errors:
        envs_str = ", ".join(environments)
        print(
            f"[INFO] S3 artifact layout validated for {git_sha}: "
            f"{len(functions)} functions x [{envs_str}] — all present"
        )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify Lambda architecture parity between CFN, deploy scripts, and S3 artifacts."
    )
    parser.add_argument(
        "--check-s3-artifacts",
        metavar="GIT_SHA",
        help="Validate S3 artifact layout for the given git SHA (requires boto3 + AWS creds).",
    )
    parser.add_argument(
        "--s3-bucket",
        default=ARTIFACT_BUCKET,
        help=f"S3 bucket for artifact validation (default: {ARTIFACT_BUCKET}).",
    )
    parser.add_argument(
        "--s3-environments",
        default="prod,gamma",
        help="Comma-separated environments to check (default: prod,gamma).",
    )
    args = parser.parse_args()

    if not COMPUTE_TEMPLATE.is_file():
        print(f"[ERROR] Compute template missing: {COMPUTE_TEMPLATE}")
        return 1

    blocks = _parse_lambda_blocks(COMPUTE_TEMPLATE)
    if not blocks:
        print("[ERROR] No Lambda functions found in compute template")
        return 1

    errors: List[str] = []

    # Validate CFN declarations
    cfn_errors = _validate_cfn(blocks)
    if cfn_errors:
        errors.append("=== CFN Architecture/Runtime violations ===")
        errors.extend(cfn_errors)

    # Validate deploy scripts
    deploy_errors = _validate_deploy_scripts()
    if deploy_errors:
        errors.append("=== Deploy script violations ===")
        errors.extend(deploy_errors)

    # Validate shared layer build script (ENC-ISS-198 / ENC-TSK-D22)
    shared_layer_errors = _validate_shared_layer_deploy_script()
    if shared_layer_errors:
        errors.append("=== Shared layer build script violations ===")
        errors.extend(shared_layer_errors)

    # Cross-validate manifest expectations (ENC-TSK-D17 AC7)
    manifest_errors = _validate_manifest_expectations()
    if manifest_errors:
        errors.append("=== Manifest expectation violations ===")
        errors.extend(manifest_errors)

    # ENC-TSK-E29: Validate S3 artifact layout when requested (E20 AC-5)
    if args.check_s3_artifacts:
        envs = [e.strip() for e in args.s3_environments.split(",") if e.strip()]
        artifact_errors = _validate_artifact_s3_layout(
            git_sha=args.check_s3_artifacts,
            bucket=args.s3_bucket,
            environments=envs,
        )
        if artifact_errors:
            errors.append("=== S3 artifact layout violations ===")
            errors.extend(artifact_errors)

    if errors:
        print("[ERROR] Lambda architecture parity check FAILED:")
        for err in errors:
            print(f"  {err}")
        return 1

    print(
        f"[SUCCESS] Lambda architecture parity valid: "
        f"{len(blocks)} CFN Lambdas use IsGamma conditionals "
        f"(prod=x86_64/py3.11, gamma=arm64/py3.12)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
