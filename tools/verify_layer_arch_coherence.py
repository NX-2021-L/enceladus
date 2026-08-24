#!/usr/bin/env python3
"""Pre-apply layer/function ARCHITECTURE coherence gate (ENC-TSK-P40 / ENC-ISS-697).

WHY THIS EXISTS
-----------------------------------------------------------------------------
ENC-ISS-696: `IsGamma` in 02-compute.yaml means "this is a suffixed non-prod
plane" -- PLANE IDENTITY -- but it was also silently selecting every
architecture-derived value, including the architecture-specific AppConfig
extension ARN. The ENC-TSK-O11 cutover flips prod to arm64 while IsGamma stays
FALSE for prod, so 26 of the 38 prod-plane functions would have rendered arm64
while still selecting `AWS-AppConfig-Extension:147`, which DECLARES
CompatibleArchitectures ["x86_64"].

ENC-ISS-697 is the general class that defect instantiates: layer/function
architecture coherence was verified only AFTER deployment.
`verify_arm64_validation_harness.py` point 2 is correct and thorough but reads
LIVE functions, so by the time it can speak the apply has already happened.
`pre-deploy-health-gate.sh` CHECK 5 covers the enceladus-shared VERSION PIN
only. `verify_lambda_arch_parity.py` checks the template's function
declarations but not the layers those same functions attach.

"The apply discovers it" is an acceptable discovery mechanism for a routine
gamma deploy that can simply be re-run. It is not acceptable for one
irreversible in-place apply across 27 production functions with no tranching,
whose only rollback is CloudFormation's stack-level revert of code AND
architecture together.

THE TWO REGIMES -- AND WHY A SINGLE POSTURE IS WRONG
-----------------------------------------------------------------------------
The fleet carries BOTH at once, and they fail in opposite directions:

  DECLARED  CompatibleArchitectures (e.g. AWS-AppConfig-Extension:147 =
            ["x86_64"], -Arm64:147 = ["arm64"]). Lambda rejects an incompatible
            attach, so the apply FAILS PARTWAY and rolls back -- loud, class-a.
            A mismatch here is a hard FAIL and is TERMINAL: it is never
            overridden by content inspection. That is load-bearing, see below.

  NULL      CompatibleArchitectures absent (e.g. enceladus-shared:10). Lambda
            permits the attach; if the payload is wrong-arch the function dies
            at INVOKE while CloudFormation reports UPDATE_COMPLETE -- silent,
            class-b. Metadata cannot settle this, so the check falls through to
            compiled-object inspection, and returns an explicit UNKNOWN when it
            cannot inspect. NEVER a silent pass.

WHY "DECLARED IS TERMINAL" IS LOAD-BEARING, NOT A STYLE CHOICE
-----------------------------------------------------------------------------
The AppConfig extension ships a SINGLE BARE ELF at `extensions/AppConfigAgent`
(x86 e_machine 0x3E, arm64 0xB7) and ZERO `.so` files. Every content inspector
in this repo globs `*.so` / `*.so.*`. A content-first design would therefore
report the x86_64 AppConfig layer as "architecture-neutral" and PASS it --
manufacturing precisely the vacuous pass ENC-ISS-696 is about. Declared
metadata is STRONGER than a .so-glob for extension layers. Hence: declared
wins, always.

ARCHITECTURES ONLY -- NEVER CompatibleRuntimes
-----------------------------------------------------------------------------
Deliberate. Under one consistent test there are 58 live runtime "violations"
across 134 attachments on a WORKING fleet -- 32 python3.12 functions on
AWS-AppConfig-Extension-Arm64:147 and 23 python3.11 on :147 (both declare
runtimes stopping at python3.9), plus 3 python3.12 on enceladus-shared:10.
Asserting CompatibleRuntimes would false-fail production as it stands today.

A NOTE ON WHAT THE FLEET'S CURRENT CLEANLINESS DOES AND DOES NOT PROVE
-----------------------------------------------------------------------------
Do NOT read "zero architecture violations live" as proof that AWS enforces the
declared field. 75 of 134 live attachments are structurally incapable of
violating (:12 declares both architectures; :10 declares null), and 55 of the
remaining 59 are the AppConfig variants whose ARN is chosen by THE SAME
condition that chose the function's architecture -- a property of the template,
not of AWS. ENC-TSK-P40 DECOUPLES that condition, which is exactly why all 31
AppConfig sites had to move with the other 93, and exactly why this gate has to
exist. The gate hard-FAILs either way; enforcement only decides whether the
failure is loud (rejected attach) or silent (dead fleet).

CONTRACT
-----------------------------------------------------------------------------
Every (function, layer) pair returns exactly one of PASS / FAIL / UNKNOWN, with
a machine-readable reason_code from a closed vocabulary. UNKNOWN is NEVER
collapsed into PASS -- the same discipline as
verify_arm64_validation_harness.py, and for the same reason: vacuous passes
have burned this platform twice (ENC-ISS-651's 29 false clears from empty
lookup lists; DVP-ISS-103's HTTP 200 with checks_errored:0 while writing
nothing).

Exit codes: 0 = every pair PASS and reconciliation held.
            1 = any FAIL or any UNKNOWN, or a reconciliation failure.
            2 = usage or environment error.

Part of ENC-TSK-P40. Wired into tools/pre-deploy-health-gate.sh as CHECK 9/9,
which the compute deploy lane already runs in its `plan` job BEFORE change-set
creation, with no continue-on-error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
CFN_DIR = REPO_ROOT / "infrastructure" / "cloudformation"
CLOSURE_PATH = REPO_ROOT / "infrastructure" / "component_dependency_closure.json"

sys.path.insert(0, str(TOOLS_DIR))

import cfn_env_resolver as R  # noqa: E402  (reuse: per-plane renderer, do not reimplement)

# ELF e_machine -> architecture. Mirrors tools/verify_lambda_package_arch.py's
# table rather than re-deriving it; imported lazily so this file stays usable
# when that module's own imports are unavailable.
ELF_MAGIC = b"\x7fELF"
ELF_MACHINE_TO_ARCH = {0x3E: "x86_64", 0xB7: "arm64"}

PASS, FAIL, UNKNOWN = "PASS", "FAIL", "UNKNOWN"

REASON_CODES = {
    "declared_match": "layer DECLARES CompatibleArchitectures and it includes the function's architecture",
    "declared_mismatch": "layer DECLARES CompatibleArchitectures and it EXCLUDES the function's architecture -- Lambda rejects this attach",
    "null_neutral": "layer declares no CompatibleArchitectures; content inspected and carries NO native objects, so it is architecture-neutral in fact",
    "null_native_match": "layer declares no CompatibleArchitectures; content inspected and every native object matches the function's architecture",
    "null_native_mismatch": "layer declares no CompatibleArchitectures; content inspected and a native object is built for a DIFFERENT architecture -- this attach succeeds and the function dies at INVOKE",
    "null_uninspectable": "layer declares no CompatibleArchitectures and its content could not be inspected -- cannot be settled from metadata, so NOT a pass",
    "arch_unresolved": "the function's Architectures did not resolve to a concrete value for this plane",
    "layer_unresolved": "the layer ARN did not resolve to a concrete string for this plane",
    "lookup_failed": "the layer's metadata could not be read (permission ceiling, network, or unknown ARN) and it is not declared in the governed closure",
}


@dataclass
class PairResult:
    function_name: str
    logical_id: str
    architecture: str
    layer_arn: str
    layer_name: str
    state: str
    reason_code: str
    detail: str = ""


@dataclass
class Report:
    plane: str
    templates: List[str] = field(default_factory=list)
    declared_functions: int = 0
    rendered_functions: int = 0
    functions_with_layers: int = 0
    attachments: int = 0
    pairs: List[PairResult] = field(default_factory=list)
    reconciliation_errors: List[str] = field(default_factory=list)
    out_of_scope: int = 0
    out_of_scope_layers: List[str] = field(default_factory=list)

    @property
    def failures(self) -> List[PairResult]:
        return [p for p in self.pairs if p.state == FAIL]

    @property
    def unknowns(self) -> List[PairResult]:
        return [p for p in self.pairs if p.state == UNKNOWN]

    @property
    def passes(self) -> List[PairResult]:
        return [p for p in self.pairs if p.state == PASS]


# ---------------------------------------------------------------------------
# Governed closure: the credential-free source of declared external-layer
# architecture. ci.yml runs without AWS credentials, so the gate must be able
# to reach a verdict from the repo alone for every layer the closure declares.
# ---------------------------------------------------------------------------
def load_closure_declarations(path: Path = CLOSURE_PATH) -> Dict[str, str]:
    """layer_arn -> declared_architecture, for every external_layer in the closure."""
    if not path.is_file():
        return {}
    out: Dict[str, str] = {}

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if node.get("kind") == "external_layer":
                arn = node.get("layer_arn")
                arch = node.get("declared_architecture")
                if arn and arch:
                    out[arn] = arch
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(json.loads(path.read_text()))
    return out


# ---------------------------------------------------------------------------
# Rendering. Reuses cfn_env_resolver end to end -- this gate is a CONSUMER of
# the existing per-plane evaluator, not a second renderer. A second renderer
# would be a second place for the two to disagree.
# ---------------------------------------------------------------------------
PLANES = {
    "prod": {"EnvironmentSuffix": "", "Environment": "production"},
    "gamma": {"EnvironmentSuffix": "-gamma", "Environment": "gamma"},
}


def render_functions(template_path: Path, plane: str) -> Tuple[int, List[Dict[str, Any]]]:
    """Return (declared_function_count, [rendered function dicts]) for one plane.

    A resource whose own `Condition` is false on this plane is NOT rendered and
    is excluded -- counting it would make the reconciliation lie.
    """
    template = R.load_template(template_path)
    ctx = R.ResolveContext(R.build_params(template, dict(PLANES[plane])))
    ctx._raw_conditions = template.get("Conditions", {}) or {}
    ctx.conditions = R.evaluate_conditions(template, ctx)

    resources = template.get("Resources") or {}
    declared = sum(
        1 for r in resources.values()
        if isinstance(r, dict) and r.get("Type") == "AWS::Lambda::Function"
    )

    rendered: List[Dict[str, Any]] = []
    for logical_id, res in resources.items():
        if not isinstance(res, dict) or res.get("Type") != "AWS::Lambda::Function":
            continue
        cond = res.get("Condition")
        if cond and not ctx.conditions.get(cond, True):
            continue
        props = res.get("Properties") or {}
        rendered.append({
            "logical_id": logical_id,
            "function_name": _scalar(R.resolve(props.get("FunctionName"), ctx)),
            "architectures": R.resolve(props.get("Architectures"), ctx),
            "layers": R.resolve(props.get("Layers"), ctx),
        })
    return declared, rendered


def _scalar(v: Any) -> str:
    if isinstance(v, str):
        return v
    return str(v)


def _one_architecture(value: Any) -> Optional[str]:
    """Architectures renders as a one-element list. Anything else is unresolved."""
    if isinstance(value, list):
        vals = [v for v in value if isinstance(v, str)]
        if len(vals) == 1:
            return vals[0]
    if isinstance(value, str):
        return value
    return None


def _layer_name(arn: str) -> str:
    try:
        return arn.split(":layer:", 1)[1]
    except (IndexError, AttributeError):
        return arn


# ---------------------------------------------------------------------------
# Layer architecture resolution: closure first (credential-free and governed),
# then AWS, then content inspection for the NULL regime.
# ---------------------------------------------------------------------------
class LayerOracle:
    def __init__(self, offline: bool, closure: Dict[str, str]) -> None:
        self.offline = offline
        self.closure = closure
        self._meta_cache: Dict[str, Any] = {}
        self._content_cache: Dict[str, Any] = {}
        self._client = None

    def _lambda(self):
        if self.offline:
            return None
        if self._client is None:
            try:
                import boto3  # noqa: WPS433
                self._client = boto3.client("lambda", region_name=os.environ.get("AWS_REGION", "us-west-2"))
            except Exception:
                self._client = False
        return self._client or None

    def declared_architectures(self, arn: str) -> Tuple[Optional[List[str]], str]:
        """(declared list or None, source). None means the layer declares nothing."""
        if arn in self.closure:
            return [self.closure[arn]], "governed-closure"
        if arn in self._meta_cache:
            return self._meta_cache[arn], "aws"
        client = self._lambda()
        if client is None:
            return None, "unavailable"
        try:
            resp = client.get_layer_version_by_arn(Arn=arn)
        except Exception as exc:  # permission ceiling, unknown ARN, network
            self._meta_cache[arn] = None
            return None, f"lookup-failed: {type(exc).__name__}"
        declared = resp.get("CompatibleArchitectures") or None
        self._meta_cache[arn] = declared
        self._content_cache.setdefault(arn, resp.get("Content", {}).get("Location"))
        return declared, "aws"

    def native_object_architectures(self, arn: str) -> Tuple[Optional[set], str]:
        """Inspect layer content for native objects. (set of arches or None, detail).

        None means the content could not be inspected at all. An empty set means
        the content was inspected and contains no native objects.
        """
        client = self._lambda()
        if client is None:
            return None, "no AWS client (offline or boto3 unavailable)"
        location = self._content_cache.get(arn)
        if not location:
            try:
                resp = client.get_layer_version_by_arn(Arn=arn)
                location = resp.get("Content", {}).get("Location")
            except Exception as exc:
                return None, f"content location unavailable: {type(exc).__name__}"
        if not location:
            return None, "no presigned content location"
        try:
            import urllib.request
            with tempfile.TemporaryDirectory() as td:
                zpath = Path(td) / "layer.zip"
                with urllib.request.urlopen(location, timeout=60) as r, open(zpath, "wb") as fh:
                    fh.write(r.read())
                found: set = set()
                inspected = 0
                with zipfile.ZipFile(zpath) as zf:
                    for info in zf.infolist():
                        if info.is_dir():
                            continue
                        head = zf.open(info).read(20)
                        inspected += 1
                        if not head.startswith(ELF_MAGIC) or len(head) < 20:
                            continue
                        # e_machine is a 2-byte LE field at offset 18 for ELF64 LE.
                        machine = int.from_bytes(head[18:20], "little")
                        found.add(ELF_MACHINE_TO_ARCH.get(machine, f"unknown-0x{machine:X}"))
                return found, f"inspected {inspected} member(s) by magic bytes"
        except Exception as exc:
            return None, f"content inspection failed: {type(exc).__name__}"


def classify_pair(fn: Dict[str, Any], arch: str, arn: str, oracle: LayerOracle) -> PairResult:
    base = dict(
        function_name=fn["function_name"], logical_id=fn["logical_id"],
        architecture=arch, layer_arn=arn, layer_name=_layer_name(arn),
    )
    declared, source = oracle.declared_architectures(arn)

    if declared:
        # DECLARED REGIME -- TERMINAL. Never overridden by content inspection.
        if arch in declared:
            return PairResult(**base, state=PASS, reason_code="declared_match",
                              detail=f"declares {declared} via {source}")
        return PairResult(**base, state=FAIL, reason_code="declared_mismatch",
                          detail=(f"function is {arch} but layer declares {declared} ({source}). "
                                  f"Lambda rejects this attach; the apply fails partway and rolls back."))

    if source.startswith("lookup-failed") or source == "unavailable":
        return PairResult(**base, state=UNKNOWN, reason_code="lookup_failed",
                          detail=f"{source}; and the layer is not declared in component_dependency_closure.json")

    # NULL REGIME -- metadata cannot settle it. Fall through to content.
    arches, detail = oracle.native_object_architectures(arn)
    if arches is None:
        return PairResult(**base, state=UNKNOWN, reason_code="null_uninspectable", detail=detail)
    if not arches:
        return PairResult(**base, state=PASS, reason_code="null_neutral", detail=detail)
    if arches == {arch}:
        return PairResult(**base, state=PASS, reason_code="null_native_match",
                          detail=f"native objects: {sorted(arches)}; {detail}")
    return PairResult(**base, state=FAIL, reason_code="null_native_mismatch",
                      detail=(f"function is {arch} but layer carries native objects for {sorted(arches)}; "
                              f"{detail}. This attach SUCCEEDS and the function dies at INVOKE while "
                              f"CloudFormation reports UPDATE_COMPLETE."))


def evaluate(plane: str, templates: List[Path], offline: bool, scope: str = "all") -> Report:
    closure = load_closure_declarations()
    oracle = LayerOracle(offline=offline, closure=closure)
    # A template may legitimately live outside REPO_ROOT: the negative control renders a
    # mutated copy from a tempdir precisely so it never touches the working tree.
    def _label(t: Path) -> str:
        try:
            return str(t.relative_to(REPO_ROOT))
        except ValueError:
            return str(t)
    rep = Report(plane=plane, templates=[_label(t) for t in templates])

    for tpl in templates:
        declared, rendered = render_functions(tpl, plane)
        rep.declared_functions += declared
        rep.rendered_functions += len(rendered)
        for fn in rendered:
            arch = _one_architecture(fn["architectures"])
            layers = fn["layers"]
            layer_arns = [l for l in (layers or []) if isinstance(l, str)]
            if layers and not layer_arns:
                rep.pairs.append(PairResult(
                    function_name=fn["function_name"], logical_id=fn["logical_id"],
                    architecture=arch or "<unresolved>", layer_arn="<unresolved>",
                    layer_name="<unresolved>", state=UNKNOWN, reason_code="layer_unresolved",
                    detail=f"Layers did not resolve to concrete strings: {layers!r}"))
                continue
            if not layer_arns:
                continue
            rep.functions_with_layers += 1
            if arch is None:
                rep.pairs.append(PairResult(
                    function_name=fn["function_name"], logical_id=fn["logical_id"],
                    architecture="<unresolved>", layer_arn=",".join(layer_arns),
                    layer_name="<multiple>", state=UNKNOWN, reason_code="arch_unresolved",
                    detail=f"Architectures did not resolve on plane {plane}: {fn['architectures']!r}"))
                continue
            for arn in layer_arns:
                if scope == "declared" and arn not in closure:
                    # SCOPE, NOT A PASS. This mode's contract is 'every attachment the
                    # governed closure can settle'. Anything else is counted and named,
                    # never silently absorbed -- and the deploy-lane invocation runs with
                    # credentials and scope=all, so nothing escapes both.
                    rep.out_of_scope += 1
                    if _layer_name(arn) not in rep.out_of_scope_layers:
                        rep.out_of_scope_layers.append(_layer_name(arn))
                    continue
                rep.attachments += 1
                rep.pairs.append(classify_pair(fn, arch, arn, oracle))

    # COUNT RECONCILIATION (ENC-TSK-P40 AC-7). Fail CLOSED on an empty or short
    # enumeration -- an architecture-coherence gate that silently examined
    # nothing would reproduce the ENC-ISS-675 / ENC-ISS-677 defect inside the
    # fix for it. Note the expectation is PER-PLANE by construction: prod and
    # gamma render different resource sets, so a single hardcoded number would
    # false-fail one of them.
    if not templates:
        rep.reconciliation_errors.append("no templates discovered -- refusing to report a vacuous pass")
    if rep.declared_functions == 0:
        rep.reconciliation_errors.append("zero AWS::Lambda::Function resources declared across the discovered templates")
    if rep.rendered_functions == 0:
        rep.reconciliation_errors.append(f"zero functions rendered on plane '{plane}' -- the renderer produced nothing to check")
    if rep.functions_with_layers and rep.attachments == 0:
        rep.reconciliation_errors.append(
            "functions carry Layers but zero attachments were evaluated -- in scope=declared this means\n             the governed closure settled NOTHING, which is a vacuous pass, not a clean run")
    if len(rep.pairs) != rep.attachments + len(
        [p for p in rep.pairs if p.reason_code in ("arch_unresolved", "layer_unresolved")]
    ):
        rep.reconciliation_errors.append(
            f"pair accounting mismatch: {len(rep.pairs)} pairs vs {rep.attachments} attachments")
    return rep


def discover(explicit: List[str]) -> List[Path]:
    if explicit:
        return [Path(p) if Path(p).is_absolute() else (REPO_ROOT / p) for p in explicit]
    # Reuse the census's own discovery so this gate's scope cannot drift from
    # it -- that is what catches 06-appsync-events.yaml, which every prior
    # count of the cutover's conditionals missed.
    try:
        import census_shared_layer_consumers as census
        names = census.discover_templates(str(CFN_DIR))
        paths = [Path(n) if os.path.isabs(n) else CFN_DIR / os.path.basename(n) for n in names]
        if paths:
            return paths
    except Exception:
        pass
    return sorted(CFN_DIR.glob("*.yaml"))


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--plane", choices=sorted(PLANES), default="prod",
                    help="which plane to render and check (default: prod)")
    ap.add_argument("--template", action="append", default=[],
                    help="explicit template path(s); default is census-based discovery")
    ap.add_argument("--offline", action="store_true",
                    help="no AWS calls; decide from component_dependency_closure.json alone "
                         "(anything it does not declare becomes UNKNOWN, never a pass)")
    ap.add_argument("--scope", choices=("all", "declared"), default="all",
                    help="'all' (default) evaluates every attachment and returns UNKNOWN for anything it "
                         "cannot settle. 'declared' restricts to attachments whose layer is declared in "
                         "component_dependency_closure.json and reports the remainder as out-of-scope -- "
                         "use it ONLY for the credential-free ci.yml lane, where the alternative is a wall "
                         "of UNKNOWNs that teaches everyone to ignore the gate.")
    ap.add_argument("--json", dest="as_json", action="store_true", help="emit the full report as JSON")
    args = ap.parse_args(argv)

    try:
        templates = discover(args.template)
        missing = [t for t in templates if not t.is_file()]
        if missing:
            print(f"[ERROR] template(s) not found: {[str(m) for m in missing]}", file=sys.stderr)
            return 2
        rep = evaluate(args.plane, templates, args.offline, args.scope)
    except Exception as exc:
        print(f"[ERROR] layer-architecture coherence gate could not run: {exc}", file=sys.stderr)
        return 2

    if args.as_json:
        print(json.dumps({
            "plane": rep.plane, "templates": rep.templates,
            "declared_functions": rep.declared_functions,
            "rendered_functions": rep.rendered_functions,
            "attachments": rep.attachments,
            "pass": len(rep.passes), "fail": len(rep.failures), "unknown": len(rep.unknowns),
            "reconciliation_errors": rep.reconciliation_errors,
            "pairs": [asdict(p) for p in rep.pairs],
        }, indent=2))

    print(f"[INFO] plane={rep.plane}  templates={len(rep.templates)}  "
          f"declared={rep.declared_functions}  rendered={rep.rendered_functions}  "
          f"attachments={rep.attachments}  scope={args.scope}")
    if rep.out_of_scope:
        print(f"[INFO] {rep.out_of_scope} attachment(s) OUT OF SCOPE for --scope=declared "
              f"(layer not declared in component_dependency_closure.json): "
              f"{sorted(rep.out_of_scope_layers)}. These are NOT passes -- the deploy-lane "
              f"invocation runs with credentials and --scope=all and covers them.")

    for p in rep.failures:
        print(f"[FAIL] {p.function_name} ({p.logical_id}): arch={p.architecture} "
              f"layer={p.layer_name} -- {p.detail}")
    for p in rep.unknowns:
        print(f"[UNKNOWN] {p.function_name} ({p.logical_id}): arch={p.architecture} "
              f"layer={p.layer_name} -- {p.detail}")
    for e in rep.reconciliation_errors:
        print(f"[FAIL] count reconciliation: {e}")

    if rep.reconciliation_errors or rep.failures or rep.unknowns:
        print(f"[ERROR] layer-architecture coherence FAILED on plane '{rep.plane}': "
              f"{len(rep.failures)} fail, {len(rep.unknowns)} unknown, "
              f"{len(rep.reconciliation_errors)} reconciliation error(s), "
              f"{len(rep.passes)} pass")
        return 1

    print(f"[SUCCESS] layer-architecture coherence: {len(rep.passes)}/{rep.attachments} "
          f"attachment(s) coherent on plane '{rep.plane}' across {rep.rendered_functions} rendered "
          f"function(s); count-reconciled against {rep.declared_functions} declared")
    return 0


if __name__ == "__main__":
    sys.exit(main())
