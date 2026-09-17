#!/usr/bin/env python3
"""ENC-TSK-Q05 AC-4 (ENC-ISS-778 P0): deploy-lane parity guard.

ENC-ISS-778's first defect existed because main's .github/workflows/_deploy.yml
and _build.yml had drifted from v4/main's copies over months (~378 and ~96
lines of diff at incident time) and main kept a pre-ARM64-cutover
x86_64-py3.11 pin for mcp_code that v4/main had long since dropped. Nothing
compared the two lanes' definitions of what gets built and what gets shipped.

main is the DISPATCH lane: a v3-prod promote runs main's own copy of these
reusable workflows against a *promoted v4/main commit*. v4/main is the gamma
lane: it runs its own copy of the same-named workflows on push. The two
files legitimately differ -- different triggers, different checkout shapes
(see the ".guard-tools" sparse checkout _build.yml's build-mcp-code job uses
specifically because the promoted tree lacks main-only tooling), different
job topology. A raw line-by-line diff between them is permanently red and
gets ignored, which is worse than no gate at all (that IS how the stale pin
survived): see ENC-TSK-Q05's design decision recorded in its worklog for why
this file compares specific, named INVARIANTS instead of the raw text.

Each invariant below is chosen to be something that:
  (1) actually determines what gets shipped (an S3 key prefix, a producer
      count, a packaging input), and
  (2) has no legitimate reason to differ between the two lanes -- so a
      divergence is always worth a human's attention, never noise.

Two testable layers:
  - Pure core: parse_key_prefix_expr(), and the extract_*()/compute_divergences()
    functions below -- take workflow text(s) in, return data out, no I/O.
  - Thin CLI: main() -- reads main's on-disk workflow files plus the other
    lane's via `git show <ref>:<path>`, and fails loudly (not silently) if
    that ref/path can't be read.

Usage:
    assert_deploy_lane_parity.py [--other-ref origin/v4/main]
        [--deploy-path .github/workflows/_deploy.yml]
        [--build-path .github/workflows/_build.yml]

Exit codes: 0 = no divergences. 1 = at least one divergence, OR the other
lane's ref/files could not be read (fail closed -- never silently skip).
2 = usage error.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# Pure core: a single divergence finding
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Divergence:
    invariant: str
    summary: str
    main_value: str
    other_value: str

    def render(self, other_label: str) -> str:
        return (
            f"[{self.invariant}] {self.summary}\n"
            f"    main:{' ' * max(1, len(other_label) - 4)}{self.main_value}\n"
            f"    {other_label}: {self.other_value}"
        )


# ---------------------------------------------------------------------------
# Pure core: extraction helpers
# ---------------------------------------------------------------------------

def _search(pattern: str, text: str, flags: int = 0) -> Optional[str]:
    m = re.search(pattern, text, flags)
    return m.group(1) if m else None


def extract_env_constant(deploy_text: str, name: str) -> Optional[str]:
    """Top-level workflow `env:` block scalar, e.g. `ARTIFACT_BUCKET: jreese-net`."""
    return _search(rf"^  {re.escape(name)}:\s*(\S+)\s*$", deploy_text, re.MULTILINE)


def extract_input_default(build_text: str, input_name: str) -> Optional[str]:
    """`workflow_call.inputs.<input_name>.default` string value."""
    return _search(
        rf'\n {{6}}{re.escape(input_name)}:\n(?:.*\n){{0,6}}?\s*default:\s*"([^"]*)"',
        build_text,
    )


def extract_resolve_key_prefix_expr(deploy_text: str) -> Optional[str]:
    """resolve job's generic `KEY_PREFIX="..."` bash assignment (the expression
    every non-overridden function's artifact key is resolved from)."""
    return _search(r'\bKEY_PREFIX="([^"]+)"', deploy_text)


def extract_resolve_mcp_code_override(deploy_text: str) -> Optional[str]:
    """resolve job's per-function `MCP_CODE_KEY_PREFIX="..."` override, if present."""
    return _search(r'\bMCP_CODE_KEY_PREFIX="([^"]+)"', deploy_text)


def extract_deploy_prefix_expr(deploy_text: str) -> Optional[str]:
    """deploy job's python `prefix = f"..."` f-string (the generic expression)."""
    return _search(r'\bprefix\s*=\s*f"([^"]+)"', deploy_text)


def extract_deploy_mcp_code_override(deploy_text: str) -> Optional[str]:
    """deploy job's python `mcp_code_prefix = "..."` literal override, if present."""
    return _search(r'\bmcp_code_prefix\s*=\s*"([^"]+)"', deploy_text)


def normalize_prefix_expr(expr: str) -> str:
    """Reduce a key-prefix expression (bash or python f-string form) to a
    canonical `<BASE>/<ARCH>-py<PY>` shape so the two lanes' different
    templating syntaxes (`${{ env.X }}` / `${ARCH}` vs an f-string's `{arch}`)
    can be compared structurally instead of textually. Any expression that
    does not reduce to that canonical shape is returned unchanged (so the
    caller still sees -- and can flag -- exactly what diverged)."""
    e = expr
    e = e.replace("${{ env.ARTIFACT_KEY_PREFIX }}", "<BASE>")
    e = e.replace("lambda-artifacts", "<BASE>")
    e = e.replace("${ARCH}", "<ARCH>").replace("{arch}", "<ARCH>")
    e = e.replace("${PY}", "<PY>").replace("{py}", "<PY>")
    return e


_CANONICAL_GENERIC_PREFIX = "<BASE>/<ARCH>-py<PY>"

_ARCH_PY_SUFFIX_RE = re.compile(r"([A-Za-z0-9_]+-py[0-9.]+)$")


def normalize_override_value(value: Optional[str]) -> Optional[str]:
    """A per-function override (resolve's `MCP_CODE_KEY_PREFIX=` bash value or
    deploy's `mcp_code_prefix =` python literal) is written with a full base
    prefix (`${{ env.ARTIFACT_KEY_PREFIX }}/...` or `lambda-artifacts/...`)
    even though the base is already asserted equal by the env-constant
    invariant above. Reduce to just the trailing `<arch>-py<pyver>` segment --
    the actual value at stake -- so the two spellings compare equal instead of
    producing a false positive purely from templating-syntax differences."""
    if value is None:
        return None
    m = _ARCH_PY_SUFFIX_RE.search(value)
    return m.group(1) if m else value


def extract_step_body(text: str, step_name: str) -> Optional[str]:
    """The text of a `- name: <step_name>` step, up to (not including) the
    next `- name:` step at the same 6-space indent, or EOF."""
    m = re.search(
        rf"- name:\s*{re.escape(step_name)}\b.*?\n(.*?)(?=\n {{6}}- name:|\Z)",
        text,
        re.DOTALL,
    )
    return m.group(1) if m else None


def extract_matrix_skip_list(build_text: str) -> List[str]:
    """Function names the matrix build loop's `case "$fn" in ... continue ;;`
    block explicitly skips (never built by the generic matrix job)."""
    step = extract_step_body(build_text, "Build + upload artifacts") or ""
    case_body = _search(r'case\s+"\$fn"\s+in(.*?)esac', step, re.DOTALL)
    if not case_body:
        return []
    names = re.findall(
        r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)\)\s*[^\n]*continue\s*;;', case_body, re.MULTILINE
    )
    return sorted(set(names))


def extract_matrix_arch_py_pairs(build_text: str) -> List[Tuple[str, str]]:
    """`(arch, py_version)` pairs from the matrix job's `strategy.matrix.include` rows."""
    return re.findall(r'-\s*arch:\s*(\S+)\s*\n\s*py_version:\s*"([^"]+)"', build_text)


def extract_dedicated_job_pins(build_text: str) -> Dict[str, str]:
    """function_name -> hardcoded key-prefix literal, for any dedicated
    per-function build job that writes `KEY="${PREFIX}/<literal>/<fn>-${SHA}.zip"`
    (main's build-mcp-code job is the current example). Distinguished from the
    generic matrix job's own key line by the uppercase bash-var spelling
    (`KEY=`/`${PREFIX}`/`${SHA}`), which the generic matrix job never uses
    (it spells these `key=`/`${{ ... }}`/`${sha}`)."""
    pins: Dict[str, str] = {}
    for prefix_literal, fn_name in re.findall(
        r'KEY="\$\{PREFIX\}/([^/"]+)/(\w+)-\$\{SHA\}\.zip"', build_text
    ):
        pins[fn_name] = prefix_literal
    return pins


def extract_mcp_code_packaging(build_text: str) -> Dict[str, Optional[str]]:
    """The mcp_code packaging-inputs signature, wherever it lives in this
    lane's _build.yml (main: the dedicated build-mcp-code job; v4/main: the
    matrix job's inline mcp_code/coordination_api/mcp_streamable/
    mcp_streaming_gateway special case). Scoped to exactly what ENC-TSK-Q05
    AC-4 names: the tools/enceladus-mcp-server/*.py glob, its test_*
    exclusion, and the mcp_server/ package reference -- NOT the
    appconfig_flags.py fallback copy or the requirements.txt path, both of
    which legitimately differ in spelling between a dedicated job's own
    tempdir and the matrix job's per-function workdir."""
    glob_source = _search(r"for py in (tools/enceladus-mcp-server/\*\.py); do", build_text)
    test_exclusion = bool(re.search(r'test_\*\)\s*continue\s*;;', build_text))
    mcp_server_ref = "tools/enceladus-mcp-server/mcp_server" in build_text
    return {
        "glob_source": glob_source,
        "test_exclusion": "yes" if test_exclusion else "no",
        "mcp_server_ref": "yes" if mcp_server_ref else "no",
    }


# ---------------------------------------------------------------------------
# Pure core: the invariant comparisons
# ---------------------------------------------------------------------------

def compute_divergences(
    main_deploy_text: str,
    other_deploy_text: str,
    main_build_text: str,
    other_build_text: str,
) -> List[Divergence]:
    divergences: List[Divergence] = []

    # --- (a) artifact key prefix expressions, resolve + deploy, generic + overrides ---

    for name in ("ARTIFACT_BUCKET", "ARTIFACT_KEY_PREFIX"):
        mv = extract_env_constant(main_deploy_text, name)
        ov = extract_env_constant(other_deploy_text, name)
        if mv != ov:
            divergences.append(Divergence(
                "deploy_env_constant:" + name,
                f"_deploy.yml's top-level env.{name} differs between lanes -- "
                "every key resolution in both jobs derives from this constant.",
                str(mv), str(ov),
            ))

    for name in ("artifact_bucket", "artifact_key_prefix"):
        mv = extract_input_default(main_build_text, name)
        ov = extract_input_default(other_build_text, name)
        if mv != ov:
            divergences.append(Divergence(
                "build_input_default:" + name,
                f"_build.yml's workflow_call.inputs.{name}.default differs "
                "between lanes.",
                str(mv), str(ov),
            ))

    main_resolve_prefix = extract_resolve_key_prefix_expr(main_deploy_text)
    other_resolve_prefix = extract_resolve_key_prefix_expr(other_deploy_text)
    _compare_generic_prefix(
        divergences, "resolve_key_prefix_generic_form",
        "resolve job's generic KEY_PREFIX expression",
        main_resolve_prefix, other_resolve_prefix,
    )

    main_deploy_prefix = extract_deploy_prefix_expr(main_deploy_text)
    other_deploy_prefix = extract_deploy_prefix_expr(other_deploy_text)
    _compare_generic_prefix(
        divergences, "deploy_key_prefix_generic_form",
        "deploy job's generic `prefix` f-string expression",
        main_deploy_prefix, other_deploy_prefix,
    )

    # Per-lane self-consistency: resolve-side and deploy-side mcp_code overrides
    # must agree WITHIN a lane whenever both are present -- this is exactly
    # the ENC-ISS-778 defect shape (one site updated, the other left stale).
    main_resolve_override = extract_resolve_mcp_code_override(main_deploy_text)
    main_deploy_override = extract_deploy_mcp_code_override(main_deploy_text)
    other_resolve_override = extract_resolve_mcp_code_override(other_deploy_text)
    other_deploy_override = extract_deploy_mcp_code_override(other_deploy_text)

    main_resolve_override_n = normalize_override_value(main_resolve_override)
    main_deploy_override_n = normalize_override_value(main_deploy_override)
    other_resolve_override_n = normalize_override_value(other_resolve_override)
    other_deploy_override_n = normalize_override_value(other_deploy_override)

    main_self_consistent = (
        main_resolve_override_n is None
        or main_deploy_override_n is None
        or main_resolve_override_n == main_deploy_override_n
    )
    other_self_consistent = (
        other_resolve_override_n is None
        or other_deploy_override_n is None
        or other_resolve_override_n == other_deploy_override_n
    )
    if not (main_self_consistent and other_self_consistent):
        divergences.append(Divergence(
            "mcp_code_override_resolve_vs_deploy_consistency",
            "A lane's resolve-job MCP_CODE_KEY_PREFIX and deploy-job "
            "mcp_code_prefix overrides must resolve to the same value -- "
            "this is the exact ENC-ISS-778 shape (one site patched, the "
            "other left on the stale pin).",
            f"resolve={main_resolve_override_n!r} deploy={main_deploy_override_n!r}",
            f"resolve={other_resolve_override_n!r} deploy={other_deploy_override_n!r}",
        ))

    # Cross-lane: when BOTH lanes define a deploy-side mcp_code override, the
    # values must match -- mcp_code's real runtime arch/py is a single fact,
    # not a per-lane opinion.
    if main_deploy_override_n is not None and other_deploy_override_n is not None:
        if main_deploy_override_n != other_deploy_override_n:
            divergences.append(Divergence(
                "mcp_code_deploy_override_cross_lane_value",
                "Both lanes define a deploy-side mcp_code_prefix override but "
                "disagree on its value.",
                main_deploy_override_n, other_deploy_override_n,
            ))

    # Direct incident catcher: within a lane, if _build.yml pins mcp_code to a
    # specific arch/py via a dedicated job, _deploy.yml's deploy-side override
    # for mcp_code (when present) must point at that same pin.
    main_build_pins = extract_dedicated_job_pins(main_build_text)
    other_build_pins = extract_dedicated_job_pins(other_build_text)

    def _pin_consistent(build_pins: Dict[str, str], deploy_override_n: Optional[str]) -> bool:
        pin = build_pins.get("mcp_code")
        if pin is None or deploy_override_n is None:
            return True
        return pin == deploy_override_n

    if not (
        _pin_consistent(main_build_pins, main_deploy_override_n)
        and _pin_consistent(other_build_pins, other_deploy_override_n)
    ):
        divergences.append(Divergence(
            "mcp_code_build_pin_vs_deploy_override_consistency",
            "_build.yml's dedicated-job artifact key pin for mcp_code must "
            "match _deploy.yml's deploy-side mcp_code_prefix override -- a "
            "build pinned to one arch/py while deploy resolves another is "
            "exactly how ENC-ISS-778 shipped an x86_64 artifact onto an "
            "arm64-only function.",
            f"build_pin={main_build_pins.get('mcp_code')!r} deploy_override={main_deploy_override_n!r}",
            f"build_pin={other_build_pins.get('mcp_code')!r} deploy_override={other_deploy_override_n!r}",
        ))

    # --- (b) function set produced + producer count per artifact key ---

    main_discovery = extract_step_body(main_build_text, "Enumerate Lambdas to build")
    other_discovery = extract_step_body(other_build_text, "Enumerate Lambdas to build")
    main_discovery_norm = " ".join((main_discovery or "").split())
    other_discovery_norm = " ".join((other_discovery or "").split())
    if main_discovery_norm != other_discovery_norm:
        divergences.append(Divergence(
            "build_discovery_command_parity",
            "_build.yml's 'Enumerate Lambdas to build' step (the `find "
            "backend/lambda ...` discovery that determines the generic "
            "matrix job's function set) differs between lanes.",
            main_discovery_norm or "<missing>",
            other_discovery_norm or "<missing>",
        ))

    main_skip = extract_matrix_skip_list(main_build_text)
    other_skip = extract_matrix_skip_list(other_build_text)
    main_uncovered = [fn for fn in main_skip if fn not in main_build_pins]
    other_uncovered = [fn for fn in other_skip if fn not in other_build_pins]
    if main_uncovered or other_uncovered:
        divergences.append(Divergence(
            "build_skip_covered_by_dedicated_job",
            "A function the generic matrix job skips must be produced by "
            "SOME job in that same lane -- an uncovered skip is exactly "
            "how a re-promote can silently deploy 0 functions for it.",
            f"skip_list={main_skip} dedicated_jobs={sorted(main_build_pins)} "
            f"uncovered={main_uncovered}",
            f"skip_list={other_skip} dedicated_jobs={sorted(other_build_pins)} "
            f"uncovered={other_uncovered}",
        ))

    main_matrix_pairs = extract_matrix_arch_py_pairs(main_build_text)
    other_matrix_pairs = extract_matrix_arch_py_pairs(other_build_text)
    main_collisions = _find_producer_collisions(main_build_pins, main_matrix_pairs, main_skip)
    other_collisions = _find_producer_collisions(other_build_pins, other_matrix_pairs, other_skip)
    if main_collisions or other_collisions:
        divergences.append(Divergence(
            "build_producer_collision",
            "A function has more than one job writing the SAME S3 artifact "
            "key (a dedicated job's pin lands on a matrix row it was not "
            "skipped from) -- this is the exact ENC-ISS-778 two-producers "
            "defect: whichever job finishes last silently wins.",
            f"collisions={main_collisions}" if main_collisions else "collisions=[]",
            f"collisions={other_collisions}" if other_collisions else "collisions=[]",
        ))

    # --- (c) mcp_code packaging inputs ---

    main_pkg = extract_mcp_code_packaging(main_build_text)
    other_pkg = extract_mcp_code_packaging(other_build_text)
    if main_pkg != other_pkg:
        divergences.append(Divergence(
            "mcp_code_packaging_inputs",
            "The mcp_code packaging inputs (tools/enceladus-mcp-server/*.py "
            "glob source, its test_* exclusion, and the mcp_server/ package "
            "reference) differ between lanes -- a silently dropped input "
            "here ships an artifact missing modules server.lambda_handler "
            "needs.",
            str(main_pkg), str(other_pkg),
        ))

    return divergences


def _compare_generic_prefix(
    divergences: List[Divergence],
    invariant: str,
    label: str,
    main_expr: Optional[str],
    other_expr: Optional[str],
) -> None:
    main_norm = normalize_prefix_expr(main_expr) if main_expr is not None else None
    other_norm = normalize_prefix_expr(other_expr) if other_expr is not None else None
    if main_norm is None or other_norm is None or main_norm != other_norm:
        divergences.append(Divergence(
            invariant,
            f"{label} must reduce to the canonical `{_CANONICAL_GENERIC_PREFIX}` "
            "shape and agree between lanes.",
            f"{main_expr!r} (normalized: {main_norm!r})",
            f"{other_expr!r} (normalized: {other_norm!r})",
        ))


def _find_producer_collisions(
    dedicated_pins: Dict[str, str],
    matrix_pairs: List[Tuple[str, str]],
    skip_list: List[str],
) -> List[str]:
    collisions = []
    for fn, literal_prefix in sorted(dedicated_pins.items()):
        if fn in skip_list:
            continue
        for arch, py in matrix_pairs:
            if f"{arch}-py{py}" == literal_prefix:
                collisions.append(f"{fn}@{literal_prefix} (matrix row {arch}-py{py} not skipped)")
    return collisions


# ---------------------------------------------------------------------------
# Thin CLI
# ---------------------------------------------------------------------------

def git_show(ref: str, path: str) -> str:
    result = subprocess.run(
        ["git", "show", f"{ref}:{path}"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git show {ref}:{path} failed (ref unavailable? did the workflow "
            f"step fetch it?): {result.stderr.strip()}"
        )
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--other-ref", default="origin/v4/main",
        help="git ref for the other lane's workflow files (default: origin/v4/main)",
    )
    parser.add_argument("--deploy-path", default=".github/workflows/_deploy.yml")
    parser.add_argument("--build-path", default=".github/workflows/_build.yml")
    args = parser.parse_args()

    try:
        main_deploy_text = (REPO_ROOT / args.deploy_path).read_text()
        main_build_text = (REPO_ROOT / args.build_path).read_text()
    except OSError as exc:
        print(f"::error::could not read main's own workflow file(s): {exc}", file=sys.stderr)
        return 1

    try:
        other_deploy_text = git_show(args.other_ref, args.deploy_path)
        other_build_text = git_show(args.other_ref, args.build_path)
    except RuntimeError as exc:
        print(
            f"::error::{exc} -- deploy-lane parity cannot be verified without "
            f"both lanes' workflow files. Failing closed rather than skipping "
            f"the check (ENC-TSK-Q05 AC-4).",
            file=sys.stderr,
        )
        return 1

    divergences = compute_divergences(
        main_deploy_text=main_deploy_text,
        other_deploy_text=other_deploy_text,
        main_build_text=main_build_text,
        other_build_text=other_build_text,
    )

    if not divergences:
        print(f"OK: main and {args.other_ref} agree on every deploy-lane parity invariant.")
        return 0

    print(
        f"::error::{len(divergences)} deploy-lane parity divergence(s) between "
        f"main and {args.other_ref}:",
        file=sys.stderr,
    )
    for d in divergences:
        print(f"::error::{d.render(args.other_ref)}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
