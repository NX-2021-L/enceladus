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
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPUTE_TEMPLATE = REPO_ROOT / "infrastructure/cloudformation/02-compute.yaml"
MANIFEST_PATH = REPO_ROOT / "infrastructure/lambda_workflow_manifest.json"
SHARED_LAYER_DEPLOY = REPO_ROOT / "backend/lambda/shared_layer/deploy.sh"

# ENC-TSK-O87: the two real arm64-dependency build paths. Neither is a
# "deploy script" in the ENVIRONMENT_SUFFIX-conditional sense the two
# constants above validate, so they get their own dedicated check.
BUILD_WORKFLOW_PATH = REPO_ROOT / ".github/workflows/_build.yml"
PACKAGE_ARTIFACT_SCRIPT = REPO_ROOT / "tools/package_lambda_artifact.sh"

# Expected structural values for prod safety. These are compared directly
# against the parsed Properties.Runtime / Properties.Architectures values
# (see LambdaResource below) rather than against raw template text, so
# formatting differences (spacing, quoting, flow vs. block YAML) can't hide
# or fabricate a violation.
EXPECTED_RUNTIME_IF: Dict[str, list] = {"!If": ["IsGamma", "python3.12", "python3.11"]}
EXPECTED_ARCH_IF_LIST: list = [{"!If": ["IsGamma", "arm64", "x86_64"]}]

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


class _CfnTagPreservingLoader(yaml.SafeLoader):
    """SafeLoader that preserves CloudFormation short-form intrinsic tags.

    PyYAML's SafeLoader raises yaml.constructor.ConstructorError on any tag
    it doesn't recognize, and CFN templates are full of short-form
    intrinsics (!Sub, !If, !Ref, !GetAtt, !Condition, !Equals, ...) that
    aren't standard YAML. Registering a multi-constructor for the bare "!"
    prefix means every such tag round-trips into an inspectable
    {"!TagName": <value>} dict instead of blowing up the parse.
    """


def _construct_cfn_tag(loader: yaml.SafeLoader, tag_suffix: str, node: yaml.Node) -> Dict[str, Any]:
    if isinstance(node, yaml.ScalarNode):
        value: Any = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    elif isinstance(node, yaml.MappingNode):
        value = loader.construct_mapping(node)
    else:  # pragma: no cover - defensive, no other yaml.Node subclass exists
        value = None
    return {f"!{tag_suffix}": value}


_CfnTagPreservingLoader.add_multi_constructor("!", _construct_cfn_tag)


@dataclass
class LambdaResource:
    """A Lambda function resource selected structurally from Resources{}.

    Replaces the old line-window LambdaBlock (ENC-TSK-O83): runtime and
    architectures are the actual parsed Properties values (str, dict, list,
    or None), not text scraped from a fixed-size window after the Type:
    declaration -- so a large Environment.Variables block or a missing
    Runtime key (container-image functions) can no longer push a function
    out of view.
    """
    resource_name: str
    function_name: str
    runtime: Any
    architectures: Any
    line_number: int


def _load_cfn_document(template_path: Path) -> tuple[dict, str]:
    text = template_path.read_text(encoding="utf-8")
    document = yaml.load(text, Loader=_CfnTagPreservingLoader) or {}
    return document, text


def _resolve_function_name(raw: Any) -> str:
    """Resolve a FunctionName property value (literal or !Sub) to a plain string."""
    if isinstance(raw, str):
        return raw
    if isinstance(raw, dict) and "!Sub" in raw:
        sub_value = raw["!Sub"]
        template = sub_value[0] if isinstance(sub_value, list) and sub_value else sub_value
        if isinstance(template, str):
            return template.replace("${EnvironmentSuffix}", "")
    return ""


def _resource_line_numbers(text: str) -> Dict[str, int]:
    """Best-effort logical-ID -> 1-based line number map, via yaml.compose().

    yaml.load() discards node position info once it constructs Python
    objects. yaml.compose() stops one step earlier and keeps the Node tree
    (with .start_mark), so we do a second, cheap pass purely to recover line
    numbers for diagnostics. Never raises: a compose failure just means
    error messages fall back to line 0, it doesn't affect resource selection.
    """
    line_numbers: Dict[str, int] = {}
    try:
        root = yaml.compose(text, Loader=_CfnTagPreservingLoader)
    except yaml.YAMLError:
        return line_numbers
    if root is None or not hasattr(root, "value"):
        return line_numbers
    for key_node, value_node in root.value:
        if getattr(key_node, "value", None) != "Resources":
            continue
        if not hasattr(value_node, "value"):
            continue
        for res_key_node, _res_value_node in value_node.value:
            line_numbers[res_key_node.value] = res_key_node.start_mark.line + 1
    return line_numbers


_LAMBDA_TYPE_LINE_RE = re.compile(r"^\s*Type:\s*AWS::Lambda::Function\s*$")


def _count_declared_lambda_resources_by_text(template_path: Path) -> int:
    """Independent census of declared Lambda resources via a raw-text scan.

    ENC-TSK-O83 AC2: deliberately does NOT reuse the YAML structural parser
    below. The whole point of the count-reconciliation assertion is to catch
    a defect in structural selection (an undercount, an exception silently
    swallowed, an unexpected document shape) -- so the number it reconciles
    against has to come from an independent method, not the same one being
    checked. A raw grep for the `Type: AWS::Lambda::Function` line is about
    as independent and as hard to accidentally break as it gets.
    """
    lines = template_path.read_text(encoding="utf-8").splitlines()
    return sum(1 for line in lines if _LAMBDA_TYPE_LINE_RE.match(line))


def _parse_lambda_blocks(template_path: Path) -> List[LambdaResource]:
    """Structurally select every AWS::Lambda::Function resource in Resources{}.

    ENC-TSK-O83: replaces the prior 40-line text-window scan, which walked
    forward from each `Type: AWS::Lambda::Function` line and silently
    dropped the function if FunctionName or Runtime hadn't appeared within
    40 lines (large Environment.Variables blocks push both out of range) or
    if Runtime was absent entirely (container-image functions). This walks
    the parsed Resources mapping directly and selects every resource of
    that Type, unconditionally -- there is no window to fall out of.
    """
    document, text = _load_cfn_document(template_path)
    resources = document.get("Resources") or {}
    line_numbers = _resource_line_numbers(text)

    blocks: List[LambdaResource] = []
    for resource_name, resource in resources.items():
        if not isinstance(resource, dict):
            continue
        if resource.get("Type") != "AWS::Lambda::Function":
            continue
        properties = resource.get("Properties") or {}
        blocks.append(
            LambdaResource(
                resource_name=resource_name,
                function_name=_resolve_function_name(properties.get("FunctionName")),
                runtime=properties.get("Runtime"),
                architectures=properties.get("Architectures"),
                line_number=line_numbers.get(resource_name, 0),
            )
        )
    return blocks


def _validate_nonzero_declared_lambdas(template_path: Path) -> List[str]:
    """Fail if the template declares zero Lambda resources at all.

    The count-reconciliation assertion alone can't catch this degenerate
    case: if nothing is declared, evaluated == declared == 0 and the counts
    trivially reconcile even though there is nothing to check. ENC-TSK-O83:
    "nothing to check" must be an explicit, visible failure -- never a
    silent pass (the ENC-ISS-651 census class: 29 false clears from empty
    lookup lists).
    """
    declared = _count_declared_lambda_resources_by_text(template_path)
    if declared == 0:
        return [
            f"Zero AWS::Lambda::Function resources declared in "
            f"{template_path.name} — the arch-parity guard has nothing to "
            f"check. Treating this as a failure, not a vacuous pass."
        ]
    return []


def _validate_resource_count_reconciliation(
    blocks: List[LambdaResource], template_path: Path
) -> List[str]:
    """ENC-TSK-O83 AC2: fail when the structural selector's count doesn't
    match an independently-derived census of declared Lambda resources.

    This is what actually closes the vacuous-pass mode Defect 1 opened: a
    parser that silently drops some functions (a bad filter, a swallowed
    exception, an unanticipated document shape) would previously report
    success on whatever subset it did see. Now the number evaluated must
    equal the number declared, or the run fails with a name-level diff.
    """
    declared = _count_declared_lambda_resources_by_text(template_path)
    evaluated = len(blocks)
    if declared != evaluated:
        document, _text = _load_cfn_document(template_path)
        resources = document.get("Resources") or {}
        declared_names = sorted(
            name
            for name, res in resources.items()
            if isinstance(res, dict) and res.get("Type") == "AWS::Lambda::Function"
        )
        evaluated_names = sorted(b.resource_name for b in blocks)
        missing = sorted(set(declared_names) - set(evaluated_names))
        extra = sorted(set(evaluated_names) - set(declared_names))
        return [
            "Lambda resource count reconciliation FAILED: "
            f"{declared} AWS::Lambda::Function resources declared in "
            f"{template_path.name} (independent raw-text census) but "
            f"{evaluated} were structurally selected and evaluated by the "
            f"arch-parity guard.",
            f"  declared={declared} evaluated={evaluated}",
            f"  declared but NOT evaluated ({len(missing)}): {', '.join(missing) or '(none)'}",
            f"  evaluated but NOT declared ({len(extra)}): {', '.join(extra) or '(none)'}",
        ]
    return []


def _is_named_architecture_exception(function_name: str, exceptions: Dict[str, Any]) -> bool:
    """True if function_name appears on any leaf list inside a manifest's
    architecture_exceptions block (any plane, any class, any architecture).

    ENC-TSK-O82: used by _validate_cfn below to defer a hardcoded-Architectures
    finding to _validate_architecture_exceptions (which knows which plane and
    which class it belongs to, and catches the both-lists contradiction) for
    any function the manifest has actually named as an exception, rather than
    unconditionally rejecting it here. A function that ISN'T named anywhere
    still gets today's unconditional rejection -- this only recognizes
    exceptions the manifest actually declares.
    """
    for plane_exceptions in exceptions.values():
        for cls in ("temporary", "permanent"):
            class_block = (plane_exceptions or {}).get(cls) or {}
            for key, value in class_block.items():
                if key in ("rationale", "terminal_state", "ratchet"):
                    continue
                if isinstance(value, list) and function_name in value:
                    return True
    return False


def _validate_cfn(
    blocks: List[LambdaResource], architecture_exceptions: Optional[Dict[str, Any]] = None
) -> List[str]:
    """Validate that all CFN Lambda declarations use IsGamma conditionals.

    ENC-TSK-O83: compares the parsed Properties.Runtime / .Architectures
    values directly against the expected structural shape (EXPECTED_RUNTIME_IF
    / EXPECTED_ARCH_IF_LIST) instead of regex-matching raw template text.

    ENC-TSK-O82: a hardcoded Architectures value is still rejected here
    unconditionally UNLESS the function is named on the manifest's
    architecture_exceptions block, in which case this defers entirely to
    _validate_architecture_exceptions (which is plane- and class-aware, and
    is what actually decides whether the exception is valid, contradictory,
    or mismatched). If architecture_exceptions isn't passed explicitly, it's
    read from the on-disk manifest at MANIFEST_PATH.
    """
    errors: List[str] = []

    if architecture_exceptions is None:
        import json
        if MANIFEST_PATH.is_file():
            manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
            architecture_exceptions = _manifest_architecture_exceptions(manifest)
        else:
            architecture_exceptions = {}

    for block in blocks:
        # ENC-TSK-F74: gamma-only literal Lambdas (e.g. enceladus-mcp-code-gamma)
        # hardcode arm64/python3.12 because they never deploy to prod. They can't
        # use !If [IsGamma, ...] because the "prod" branch would also be created
        # (IsGamma is false when EnvironmentSuffix="") and collide with the live
        # gamma resource. Skip arch/runtime parity on these — they're gamma-only
        # by definition, and the !If invariant doesn't apply.
        if block.function_name.endswith("-gamma"):
            continue

        label = f"{block.function_name or block.resource_name} ({block.resource_name}, line {block.line_number})"

        # Check Runtime
        if block.runtime != EXPECTED_RUNTIME_IF:
            if isinstance(block.runtime, str):
                errors.append(
                    f"{label}: hardcoded Runtime={block.runtime}, expected "
                    f"!If [IsGamma, python3.12, python3.11]"
                )
            elif block.runtime is None:
                errors.append(
                    f"{label}: missing Runtime property (container-image "
                    f"functions must still be explicitly exempted, not "
                    f"silently skipped)"
                )
            else:
                errors.append(
                    f"{label}: unexpected Runtime value: {block.runtime!r}, "
                    f"expected !If [IsGamma, python3.12, python3.11]"
                )

        # Check Architectures
        if block.architectures != EXPECTED_ARCH_IF_LIST:
            if _is_named_architecture_exception(block.function_name, architecture_exceptions):
                pass  # ENC-TSK-O82: deferred to _validate_architecture_exceptions
            elif (
                isinstance(block.architectures, list)
                and len(block.architectures) == 1
                and isinstance(block.architectures[0], str)
            ):
                errors.append(
                    f"{label}: hardcoded Architectures=[{block.architectures[0]}], "
                    f"expected !If [IsGamma, arm64, x86_64]"
                )
            elif block.architectures is None:
                errors.append(f"{label}: missing Architectures property")
            else:
                errors.append(
                    f"{label}: unexpected Architectures value: "
                    f"{block.architectures!r}, expected "
                    f"[!If [IsGamma, arm64, x86_64]]"
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

    # ENC-TSK-F59: script tombstoned — artifact build moved to _deploy.yml matrix
    if content.strip().startswith("# TOMBSTONE:"):
        print(
            "[INFO] shared_layer/deploy.sh is tombstoned — ABI flag validation skipped"
            " (artifact build handled by .github/workflows/_deploy.yml)"
        )
        return []

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


# ENC-TSK-O87: the four flags every arm64 dependency build must pass. Order
# in the tuple has no meaning; presence is checked independently per flag.
REQUIRED_PIP_ARCH_FLAGS: tuple = (
    "--platform",
    "--implementation cp",
    "--python-version",
    "--only-binary=:all:",
)


def _extract_shell_command_block(text: str, anchor: str) -> Optional[str]:
    """Return the backslash-continued shell command starting at `anchor`.

    Scans line-by-line from the first occurrence of `anchor`, including every
    subsequent line that is part of the same continued command (a line ending
    in ``\``), and stops at (and includes) the first line that does not end
    in a continuation backslash — i.e. the line that actually terminates the
    shell command. Returns None if `anchor` is not found in `text`.

    This mirrors how both real invocations are written: multi-line pip
    installs with a trailing ``\`` on every line but the last.
    """
    idx = text.find(anchor)
    if idx == -1:
        return None
    block_lines: List[str] = []
    for line in text[idx:].splitlines():
        block_lines.append(line)
        if not line.rstrip().endswith("\\"):
            break
    return "\n".join(block_lines)


def _validate_build_invocation_flags() -> List[str]:
    """ENC-TSK-O87: assert both real arm64-dependency build invocations still
    carry the full pip flag contract, so the contract is enforced
    structurally instead of by one-time inspection.

    BRD Sec 6.5: "The build invocation is therefore part of the contract,
    not an implementation detail." Without --only-binary=:all: specifically,
    a missing aarch64 wheel makes pip silently fall back to a source build
    or an older version instead of failing CI loudly (ENC-TSK-O87 AC-2,
    observed at https://github.com/NX-2021-L/enceladus/actions/runs/32615808666).

    Checks two paths — there is no third; deploy.sh / shared_layer/deploy.sh
    are tombstoned and validated separately, and _deploy.yml has no
    independent install path of its own (it only calls _build.yml):
      1. .github/workflows/_build.yml — the Gen2 matrix build (one shared
         `python -m pip install` invocation, arch selected via
         matrix.pip_platform).
      2. tools/package_lambda_artifact.sh — the legacy per-function build
         invoked by build-lambda-artifacts.yml.
    """
    errors: List[str] = []

    checks = (
        ("_build.yml", BUILD_WORKFLOW_PATH, "python -m pip install"),
        ("package_lambda_artifact.sh", PACKAGE_ARTIFACT_SCRIPT, "pip install"),
    )

    for label, path, anchor in checks:
        if not path.is_file():
            errors.append(f"{label}: file not found at {path}")
            continue

        text = path.read_text(encoding="utf-8")
        block = _extract_shell_command_block(text, anchor)
        if block is None:
            errors.append(
                f"{label}: no '{anchor}' invocation found. The arm64 wheel "
                f"contract (ENC-TSK-O87) can't be verified because this "
                f"build path no longer installs dependencies via pip, or "
                f"the invocation no longer starts with '{anchor}'."
            )
            continue

        for flag in REQUIRED_PIP_ARCH_FLAGS:
            if flag not in block:
                errors.append(
                    f"{label}: pip install invocation is missing required "
                    f"flag '{flag}' (ENC-TSK-O87 aarch64 wheel contract, "
                    f"BRD Sec 6.5). Without every one of "
                    f"{', '.join(REQUIRED_PIP_ARCH_FLAGS)}, a missing "
                    f"aarch64 wheel silently falls back to a source build "
                    f"or a stale version instead of failing CI loudly."
                )

    if not errors:
        # Deliberately not path.relative_to(REPO_ROOT) here: tests mock
        # BUILD_WORKFLOW_PATH / PACKAGE_ARTIFACT_SCRIPT to tempfiles outside
        # REPO_ROOT, and an [INFO] print crashing on relative_to() would be
        # exactly the kind of guard-goes-vacuously-green-by-accident bug
        # this check exists to prevent elsewhere. Labels are stable regardless
        # of what's mocked underneath them.
        checked_labels = ", ".join(label for label, _, _ in checks)
        print(
            f"[INFO] Build invocation flag contract validated: both "
            f"{checked_labels} carry {', '.join(REQUIRED_PIP_ARCH_FLAGS)}"
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

    # ENC-TSK-O83 Defect 3: previously `return []` here — a manifest with no
    # expected_architecture/expected_runtime keys at all (malformed,
    # truncated, or a bad hand-edit) silently passed this check because
    # there was "nothing to validate". That's the same vacuous-pass shape as
    # Defects 1 and 2, just in a third place. Absent expectations must now
    # fail, not skip.
    if not expected_arch or not expected_runtime:
        return [
            "Manifest is missing expected_architecture and/or "
            "expected_runtime keys entirely. A malformed or truncated "
            "manifest must fail this guard, not silently skip validation "
            "(ENC-TSK-O83)."
        ]

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


def _manifest_architecture_exceptions(manifest: dict) -> Dict[str, Any]:
    """Read point for the manifest's two-class `architecture_exceptions` block.

    ENC-TSK-O83 left this as an unwired seam. ENC-TSK-O82 (BRD DOC-56CFA21523C1
    section 6.2) wires it via _validate_architecture_exceptions() below: each
    plane's exceptions carry a `temporary` class (monotonically shrinking,
    terminal state empty) and a `permanent` class (stable; additions require
    an io ruling), each keyed by the deviant architecture string (e.g.
    "x86_64") to the list of function names carrying that deviation.
    """
    return manifest.get("architecture_exceptions", {})


def _resolve_plane_architecture(architectures: Any, plane: str) -> Optional[str]:
    """Resolve a LambdaResource.architectures value to a single string for
    one deploy plane ("prod" or "gamma").

    Two shapes are understood:
      - The IsGamma conditional list (EXPECTED_ARCH_IF_LIST): resolves to
        "arm64" on the gamma plane and "x86_64" on the prod plane -- the
        same fixed literals _validate_cfn compares the raw property against
        structurally.
      - A hardcoded single-element list (e.g. ["arm64"]): that literal value
        applies on every plane, since nothing conditions it on IsGamma.

    Anything else (missing Architectures, an unrecognized shape) resolves to
    None. The caller treats an unresolved architecture as a mismatch against
    the plane's target -- it can only pass by exception, never by matching.
    """
    if architectures == EXPECTED_ARCH_IF_LIST:
        return "arm64" if plane == "gamma" else "x86_64"
    if (
        isinstance(architectures, list)
        and len(architectures) == 1
        and isinstance(architectures[0], str)
    ):
        return architectures[0]
    return None


def _validate_architecture_exceptions(blocks: List[LambdaResource]) -> List[str]:
    """ENC-TSK-O82: enforce the two-class architecture_exceptions contract
    (BRD DOC-56CFA21523C1 section 6.2) declared in the manifest.

    For every plane the manifest declares an architecture_exceptions entry
    for (today: "prod" only -- see the manifest's own rationale for why
    expected_architecture.prod has not yet flipped to arm64; per io's Q2
    ruling on ENC-PLN-082 that flip happens at the start of BRD Phase 5,
    simultaneously with populating both exception classes, which is that
    plan's call and not this gamma-only task's), each non-"-gamma" function
    passes when its resolved architecture for that plane either:

      (a) matches manifest.expected_architecture[plane], or
      (b) appears on exactly one of the plane's two exception classes
          (temporary, permanent) under that resolved architecture value.

    A function listed on BOTH classes for the same resolved architecture is
    a contradiction -- an exception cannot simultaneously be a stable,
    permanent decision and a shrinking, temporary one -- and fails
    regardless of whether it also matches the target. A function matching
    neither the target nor exactly one exception list fails.

    Does not implement the ratchet check itself (whether a class's
    membership only ever moves the direction its own "ratchet" field
    promises, release over release) -- that is ENC-TSK-O84. This only
    checks that today's manifest + CFN state is internally consistent.
    """
    errors: List[str] = []

    import json
    if not MANIFEST_PATH.is_file():
        return ["Lambda workflow manifest not found"]

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    expected_arch = manifest.get("expected_architecture", {})
    exceptions = _manifest_architecture_exceptions(manifest)

    for plane, plane_exceptions in exceptions.items():
        target = expected_arch.get(plane)
        temporary = (plane_exceptions or {}).get("temporary") or {}
        permanent = (plane_exceptions or {}).get("permanent") or {}

        for block in blocks:
            if block.function_name.endswith("-gamma"):
                continue  # gamma-only literals never participate in prod/gamma parity

            name = block.function_name or block.resource_name
            resolved = _resolve_plane_architecture(block.architectures, plane)

            temp_list = temporary.get(resolved, []) if resolved else []
            perm_list = permanent.get(resolved, []) if resolved else []
            on_temp = name in temp_list
            on_perm = name in perm_list

            if on_temp and on_perm:
                errors.append(
                    f"{name} ({plane}): listed on BOTH the temporary and "
                    f"permanent architecture_exceptions classes for "
                    f"{resolved!r} -- an exception must be exactly one or "
                    f"the other."
                )
                continue

            if resolved == target:
                continue

            if on_temp or on_perm:
                continue

            errors.append(
                f"{name} ({plane}): resolved architecture {resolved!r} does "
                f"not match target {target!r} and is not listed on either "
                f"architecture_exceptions class."
            )

    return errors


# ---------------------------------------------------------------------------
# ENC-TSK-O84 (ENC-PLN-086 Wave 2, ENC-FTR-135): monotonic ratchet on the
# temporary exception class, and an io-ruling gate on permanent-class growth.
#
# ENC-TSK-O82 wired the two-class contract (a function is exempt if it's
# named on exactly one of temporary/permanent) but explicitly left the
# ratchet itself unimplemented -- that a class's membership only ever moves
# the direction its own "ratchet" field promises, release over release, is
# this task's job. Neither class's ratchet is enforceable by reading the
# manifest alone: "may only shrink" and "additions require an io ruling" are
# both properties of a *transition*, not of a single snapshot. Both checks
# below therefore take a `baseline` and a `current` architecture_exceptions
# dict and diff them, rather than inspecting either one in isolation.
# ---------------------------------------------------------------------------

_EXCEPTION_CLASS_METADATA_KEYS = ("rationale", "terminal_state", "ratchet")

# Required citation shape for a permanent-class addition: the literal marker
# "io ruling:" (case-insensitive) followed by a tracker-record-ID-shaped
# token, e.g. "io ruling: ENC-TSK-0102" or "io ruling: DVP-ISS-14". This is
# deliberately loose about the ID's prefix/shape (this repo runs several:
# ENC-TSK-, ENC-ISS-, DVP-TSK-, ...) and strict about the marker itself,
# since the marker -- not the ID format -- is what makes an addition
# reviewable rather than silent.
_IO_RULING_RE = re.compile(
    r"io ruling\s*:\s*([A-Za-z]{2,5}-[A-Za-z]{2,5}-[A-Za-z0-9]+)",
    re.IGNORECASE,
)


def _class_name_sets(class_block: Optional[Dict[str, Any]]) -> Dict[str, set]:
    """Map each architecture key in a temporary/permanent class block to the
    set of function names listed under it, skipping the class's own
    rationale/terminal_state/ratchet metadata keys.

    Pure and manifest-shape-only: takes an already-parsed class dict (e.g.
    architecture_exceptions["prod"]["temporary"]), never touches disk or
    git. That's what makes diff_architecture_exceptions() below directly
    unit-testable against synthetic before/after manifests (ENC-TSK-O84
    AC-1/AC-2) without needing a real git history, or either of the real
    exception lists (both empty today) to have anything in them.
    """
    result: Dict[str, set] = {}
    for key, value in (class_block or {}).items():
        if key in _EXCEPTION_CLASS_METADATA_KEYS:
            continue
        if isinstance(value, list):
            result[key] = set(value)
    return result


def _ruling_tokens(class_block: Optional[Dict[str, Any]]) -> set:
    """Extract every 'io ruling: <RECORD-ID>' citation token from a class's
    rationale prose (case-insensitive marker, any tracker-ID-shaped token).
    """
    rationale = (class_block or {}).get("rationale") or ""
    if not isinstance(rationale, str):
        return set()
    return {match.group(1) for match in _IO_RULING_RE.finditer(rationale)}


def diff_architecture_exceptions(
    baseline: Dict[str, Any], current: Dict[str, Any]
) -> List[str]:
    """ENC-TSK-O84: enforce both exception-class ratchets across a
    baseline -> current transition of the manifest's architecture_exceptions
    block.

    Pure function -- baseline and current are already-parsed
    architecture_exceptions dicts (e.g. manifest["architecture_exceptions"]),
    never file paths or git refs -- so both AC-1 and AC-2 can be proven with
    synthetic manifests in unit tests, independent of git plumbing and of
    the real exception lists (both empty today; see ENC-TSK-O82/ENC-TSK-O72).

    AC-1 (temporary ratchet): for every plane and every architecture key
    under a `temporary` class, current membership must be a subset of
    baseline membership. Any name present at `current` but absent at
    `baseline` is a ratchet violation -- growth requires a deliberate
    baseline update (moving what this function is diffed against), not a
    silent edit. Shrinking, or no change, is always allowed -- that's the
    entire point of the class existing.

    AC-2 (permanent ruling gate): for every plane and every architecture key
    under a `permanent` class, a name added relative to baseline is an
    undocumented decision UNLESS the plane's permanent-class rationale text
    ALSO gained a fresh `io ruling: <RECORD-ID>` citation in this same
    baseline -> current transition. A citation already present at baseline
    does not count: it can't be evidence of a ruling on an addition that
    didn't exist yet, and would let one stale citation silently cover every
    future addition forever. The citation is required once per growth
    event (not once per function name), matching the manifest's existing
    plane+class-scoped -- not per-function -- rationale granularity.

    Returns a list of human-readable violation strings that name exactly
    which entries were added and where; an empty list means both class
    contracts hold.
    """
    errors: List[str] = []
    planes = sorted(set(baseline.keys()) | set(current.keys()))

    for plane in planes:
        baseline_plane = baseline.get(plane) or {}
        current_plane = current.get(plane) or {}

        # --- AC-1: the temporary class may only shrink ---
        temp_baseline = _class_name_sets(baseline_plane.get("temporary"))
        temp_current = _class_name_sets(current_plane.get("temporary"))
        for arch in sorted(set(temp_baseline.keys()) | set(temp_current.keys())):
            added = temp_current.get(arch, set()) - temp_baseline.get(arch, set())
            if added:
                errors.append(
                    f"architecture_exceptions.{plane}.temporary.{arch}: "
                    f"ratchet violation -- grew by {sorted(added)} relative "
                    f"to the baseline. The temporary class may only shrink; "
                    f"growth requires a deliberate baseline update, not a "
                    f"silent edit (ENC-TSK-O84 AC-1)."
                )

        # --- AC-2: permanent-class additions require a fresh io ruling ---
        perm_baseline = _class_name_sets(baseline_plane.get("permanent"))
        perm_current = _class_name_sets(current_plane.get("permanent"))
        perm_added: Dict[str, set] = {}
        for arch in sorted(set(perm_baseline.keys()) | set(perm_current.keys())):
            added = perm_current.get(arch, set()) - perm_baseline.get(arch, set())
            if added:
                perm_added[arch] = added

        if perm_added:
            ruling_baseline = _ruling_tokens(baseline_plane.get("permanent"))
            ruling_current = _ruling_tokens(current_plane.get("permanent"))
            new_rulings = ruling_current - ruling_baseline
            if not new_rulings:
                for arch, added in perm_added.items():
                    errors.append(
                        f"architecture_exceptions.{plane}.permanent.{arch}: "
                        f"un-ruled addition -- grew by {sorted(added)} "
                        f"without a fresh 'io ruling: <RECORD-ID>' citation "
                        f"added to the permanent class's rationale in this "
                        f"change. Permanent-class entries are decisions, not "
                        f"debt -- they may not pass silently (ENC-TSK-O84 "
                        f"AC-2)."
                    )
            else:
                for arch, added in perm_added.items():
                    print(
                        f"[INFO] architecture_exceptions.{plane}.permanent."
                        f"{arch}: grew by {sorted(added)}, covered by fresh "
                        f"ruling citation(s): {sorted(new_rulings)}"
                    )

    return errors


def _git_show_manifest_at_ref(ref: str) -> Optional[dict]:
    """Read infrastructure/lambda_workflow_manifest.json as it existed at
    `ref`, via `git show`, without touching the working tree or requiring a
    second on-disk artifact -- history is the baseline.

    Returns None if the ref/path can't be resolved (unknown ref, a shallow
    clone missing the needed history, or the file not yet existing at that
    ref). Callers must treat that as a hard failure, not a silent skip: an
    unresolvable baseline is not evidence of an empty one (ENC-TSK-O83
    vacuous-pass lesson -- "nothing to check" must be visible, never quiet).
    """
    import json

    try:
        rel_path = MANIFEST_PATH.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        rel_path = "infrastructure/lambda_workflow_manifest.json"

    proc = subprocess.run(
        ["git", "show", f"{ref}:{rel_path}"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def _validate_architecture_exceptions_ratchet(base_ref: str) -> List[str]:
    """ENC-TSK-O84: CI-facing glue for diff_architecture_exceptions().

    The baseline is the same manifest file at `base_ref` (the PR's base sha
    for a pull_request event, or the previous commit for a direct push),
    read via `git show` -- no new committed artifact. `current` is the
    on-disk manifest at HEAD, i.e. the working tree CI just checked out.
    Comparing the file to its own history means the ratchet naturally scopes
    to exactly what this change did, with no second file to keep in sync
    or let drift.
    """
    baseline_manifest = _git_show_manifest_at_ref(base_ref)
    if baseline_manifest is None:
        return [
            f"Could not read infrastructure/lambda_workflow_manifest.json "
            f"at base ref {base_ref!r} via `git show` -- cannot evaluate "
            f"the architecture_exceptions ratchet. Treating an unresolvable "
            f"baseline as a hard failure, not a silent skip (ENC-TSK-O83 "
            f"vacuous-pass lesson). Check that the checkout has enough "
            f"history (fetch-depth: 0) and that {base_ref!r} is a valid ref."
        ]

    if not MANIFEST_PATH.is_file():
        return ["Lambda workflow manifest not found"]

    import json

    current_manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    baseline_exceptions = _manifest_architecture_exceptions(baseline_manifest)
    current_exceptions = _manifest_architecture_exceptions(current_manifest)
    return diff_architecture_exceptions(baseline_exceptions, current_exceptions)


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
    parser.add_argument(
        "--exceptions-base-ref",
        metavar="REF",
        help=(
            "Git ref/sha to diff infrastructure/lambda_workflow_manifest.json's "
            "architecture_exceptions block against: fails when the temporary "
            "class grew, or when the permanent class grew without a fresh "
            "'io ruling: <RECORD-ID>' citation (ENC-TSK-O84). Omit to skip "
            "the ratchet (e.g. for a plain local structural check)."
        ),
    )
    args = parser.parse_args()

    if not COMPUTE_TEMPLATE.is_file():
        print(f"[ERROR] Compute template missing: {COMPUTE_TEMPLATE}")
        return 1

    blocks = _parse_lambda_blocks(COMPUTE_TEMPLATE)

    errors: List[str] = []

    # ENC-TSK-O83: "nothing to check" must be an explicit failure, never a
    # silent pass. Run before anything else so an empty or malformed
    # Resources block can't slip through as a trivially-reconciled 0 == 0.
    nonzero_errors = _validate_nonzero_declared_lambdas(COMPUTE_TEMPLATE)
    if nonzero_errors:
        errors.append("=== Lambda resource census violations ===")
        errors.extend(nonzero_errors)

    # ENC-TSK-O83 AC2: count-reconciliation assertion. Independently counts
    # declared Lambda resources and fails when that count does not equal
    # the number the structural selector actually evaluated.
    reconciliation_errors = _validate_resource_count_reconciliation(blocks, COMPUTE_TEMPLATE)
    if reconciliation_errors:
        errors.append("=== Lambda resource count reconciliation violations ===")
        errors.extend(reconciliation_errors)

    # Validate CFN declarations
    cfn_errors = _validate_cfn(blocks)
    if cfn_errors:
        errors.append("=== CFN Architecture/Runtime violations ===")
        errors.extend(cfn_errors)

    # ENC-TSK-O82: validate the two-class architecture_exceptions contract
    exceptions_errors = _validate_architecture_exceptions(blocks)
    if exceptions_errors:
        errors.append("=== Architecture exceptions contract violations ===")
        errors.extend(exceptions_errors)

    # ENC-TSK-O84: monotonic ratchet (temporary) + permanent-class ruling
    # gate, diffed against the base ref a CI run supplies. Skipped (not
    # vacuously passed) when no base ref is given -- there is genuinely
    # nothing to diff against for a plain local structural check.
    if args.exceptions_base_ref:
        ratchet_errors = _validate_architecture_exceptions_ratchet(
            args.exceptions_base_ref
        )
        if ratchet_errors:
            errors.append(
                "=== Architecture exceptions ratchet violations (ENC-TSK-O84) ==="
            )
            errors.extend(ratchet_errors)
        else:
            print(
                f"[INFO] Architecture exceptions ratchet clear against "
                f"{args.exceptions_base_ref}: temporary class did not grow, "
                f"no un-ruled permanent-class additions."
            )

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

    # ENC-TSK-O87: assert the aarch64 wheel contract survives on both real
    # arm64-dependency build paths, not just at the time someone inspected it.
    build_invocation_errors = _validate_build_invocation_flags()
    if build_invocation_errors:
        errors.append("=== Build invocation flag violations ===")
        errors.extend(build_invocation_errors)

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
        f"{len(blocks)} CFN Lambdas structurally selected and evaluated "
        f"(count-reconciled against an independent census), all use "
        f"IsGamma conditionals (prod=x86_64/py3.11, gamma=arm64/py3.12)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
