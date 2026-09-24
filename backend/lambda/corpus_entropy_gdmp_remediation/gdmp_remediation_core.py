"""gdmp_remediation_core — pure-function GDMP Stage-1 auto-remediation logic.

ENC-TSK-K42 / B66 Phase-5 (ENC-PLN-064, parent ENC-TSK-B66), per DOC-A3D0CDF91CE9.
Consumes the Compliance/Semantic detector output shipped in K41
(corpus_entropy_core.detect_compliance_semantic_entropy) and deterministically
resolves a narrow whitelist of `compliance_warnings` classes so raw documents
can advance to `compliant` maturity without agent involvement.

This module is network-free and unit-testable in isolation; the Lambda's HTTP
calls (document GET/PATCH against document_api) live in lambda_function.py,
mirroring the corpus_entropy_core / lambda_function split established by K41.

DATA-SAFETY (AC-2):
  * Only a fixed whitelist of deterministic, structure-only warning classes is
    auto-remediated (`DETERMINISTIC_WARNING_CLASSIFIERS` below). Every other
    warning (title format, empty document, heading hierarchy, list-marker
    consistency, table dividers, malformed alerts, COE section gaps) is
    left untouched for agent/human review — remediating those would require
    guessing at document *meaning*, not just structure.
  * Remediation never invents prose. It only inserts placeholder metadata
    lines / language tags that a human or agent later fills in — the
    resulting text is a strict superset of the original content.

io-approval ramp (AC-3): reuses the exact FTR-106 / ENC-TSK-K03 pattern
(unlearning_core.mutation_allowed / io_approval_ramp_active) — a persisted
run counter gates live runs to candidate-report-only until IO_APPROVAL_RUNS
successful dry-run cycles have been observed and mutation mode is explicitly
enabled by io.

Idempotency (AC-4): `plan_remediation` is a no-op (no whitelisted warnings,
no content change) when a document has no matching warnings, and
`remediate_content` is stable under repeated application — applying it twice
to already-remediated content yields the same content unchanged (each fixer
checks for its own applied marker before acting again).
"""

from __future__ import annotations

import os
import re
from typing import Any, Callable, Dict, List, Optional, Sequence

COST_PREFLIGHT_MONTHLY_USD = 0.10
GDMP_REPORT_SUBTYPEPATTERN = "gdmp-stage1-candidate"

# ---------------------------------------------------------------------------
# DATA-SAFETY whitelist: deterministic, structure-only warning classes.
#
# Each entry maps a `reason`/pattern key to a matcher (identifies whether a
# raw compliance_warnings string belongs to this class) and a fixer (pure
# function content -> content). Anything not matched here is left alone.
# ---------------------------------------------------------------------------

_FENCE_LANG_RE = re.compile(r"^Code fence at line (\d+) should include a language identifier\.$")
_METADATA_FIELD_RE = re.compile(r"^Metadata block missing '\*\*(\w+)\*\*:' near top of document\.$")

DEFAULT_FENCE_LANGUAGE = "text"


def _classify_fence_missing_language(warning: str) -> Optional[Dict[str, Any]]:
    m = _FENCE_LANG_RE.match(warning.strip())
    if not m:
        return None
    return {"class": "fence_missing_language", "line": int(m.group(1))}


def _classify_metadata_field_missing(warning: str) -> Optional[Dict[str, Any]]:
    m = _METADATA_FIELD_RE.match(warning.strip())
    if not m:
        return None
    return {"class": "metadata_field_missing", "field": m.group(1)}


# Ordered list of (classifier) -- order matters only for readability; fixers
# are independent and commute against disjoint parts of the document.
DETERMINISTIC_WARNING_CLASSIFIERS: Sequence[Callable[[str], Optional[Dict[str, Any]]]] = (
    _classify_fence_missing_language,
    _classify_metadata_field_missing,
)

# Metadata fields recognized by document_api._evaluate_markdown_compliance's
# Rule 1+7 scan (backend/lambda/document_api/lambda_function.py), in the
# canonical order they're checked.
KNOWN_METADATA_FIELDS = ("Project", "Related", "Created", "Author")


def classify_warning(warning: str) -> Optional[Dict[str, Any]]:
    """Return a classification dict if `warning` matches a deterministic
    whitelisted class, else None (ambiguous/content-changing -> leave alone).
    """
    for classifier in DETERMINISTIC_WARNING_CLASSIFIERS:
        result = classifier(warning)
        if result is not None:
            return result
    return None


def partition_warnings(warnings: Sequence[str]) -> Dict[str, List[Any]]:
    """Split compliance_warnings into deterministic (whitelisted, auto-fixable)
    vs. ambiguous (left for agent/human review) buckets.
    """
    deterministic: List[Dict[str, Any]] = []
    ambiguous: List[str] = []
    for w in warnings or []:
        classification = classify_warning(w)
        if classification is not None:
            classification["warning"] = w
            deterministic.append(classification)
        else:
            ambiguous.append(w)
    return {"deterministic": deterministic, "ambiguous": ambiguous}


# ---------------------------------------------------------------------------
# Fixers -- pure content -> content transforms. Additive only (never deletes
# or rewrites existing lines), so remediation is always a strict superset of
# the original content and safe to re-run (idempotent).
# ---------------------------------------------------------------------------

def _fix_fence_missing_language(content: str) -> str:
    """Insert DEFAULT_FENCE_LANGUAGE on every opening fence line missing a
    language identifier. Idempotent: a fence that already has a language tag
    (including one this function previously added) is left untouched.
    """
    lines = content.splitlines(keepends=False)
    out: List[str] = []
    in_fence = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            if not in_fence:
                in_fence = True
                lang = stripped[3:].strip()
                if not lang:
                    indent = line[: len(line) - len(line.lstrip())]
                    out.append(f"{indent}```{DEFAULT_FENCE_LANGUAGE}")
                    continue
            else:
                in_fence = False
        out.append(line)
    result = "\n".join(out)
    if content.endswith("\n") and not result.endswith("\n"):
        result += "\n"
    return result


def _fix_metadata_field_missing(content: str, field: str) -> str:
    """Insert a `**Field**: TBD` placeholder line into the metadata block near
    the top of the document. Idempotent: if the field label is already present
    anywhere in the metadata window, no change is made.

    Insertion point: immediately after the title line (first non-empty line)
    if it's a heading, else at the very top. This mirrors the metadata-window
    scan in document_api._evaluate_markdown_compliance (first 30 lines).
    """
    if f"**{field}**:" in "\n".join(content.splitlines()[:30]):
        return content  # already present -- idempotent no-op

    lines = content.splitlines(keepends=False)
    first_non_empty_idx = None
    for idx, line in enumerate(lines):
        if line.strip():
            first_non_empty_idx = idx
            break

    placeholder = f"**{field}**: TBD"
    if first_non_empty_idx is None:
        new_lines = [placeholder]
    elif lines[first_non_empty_idx].lstrip().startswith("#"):
        insert_at = first_non_empty_idx + 1
        new_lines = lines[:insert_at] + ["", placeholder] + lines[insert_at:]
    else:
        new_lines = [placeholder, ""] + lines

    result = "\n".join(new_lines)
    if content.endswith("\n") and not result.endswith("\n"):
        result += "\n"
    return result


def remediate_content(content: str, deterministic_findings: Sequence[Dict[str, Any]]) -> str:
    """Apply every whitelisted deterministic fixer for this document's
    findings, in a stable order (fence fixes before metadata fixes), and
    return the remediated content. Pure function; never mutates input.
    """
    remediated = content
    if any(f["class"] == "fence_missing_language" for f in deterministic_findings):
        remediated = _fix_fence_missing_language(remediated)
    metadata_fields = sorted(
        {f["field"] for f in deterministic_findings if f["class"] == "metadata_field_missing"},
        key=lambda name: KNOWN_METADATA_FIELDS.index(name) if name in KNOWN_METADATA_FIELDS else 99,
    )
    for field in metadata_fields:
        remediated = _fix_metadata_field_missing(remediated, field)
    return remediated


# ---------------------------------------------------------------------------
# Remediation plan -- decides whether a document is a no-op, a
# fully-deterministic candidate, or requires agent review (has ambiguous
# warnings that the whitelist cannot resolve).
# ---------------------------------------------------------------------------

def plan_remediation(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Build a remediation plan for a single Compliance/Semantic finding
    (the shape produced by corpus_entropy_core.detect_compliance_semantic_entropy,
    joined with the document's full compliance_warnings list by the caller).

    Returns a dict describing what would happen -- callers combine this with
    io-approval-ramp state to decide whether to actually PATCH.
    """
    record_id = finding.get("record_id") or ""
    warnings = finding.get("compliance_warnings") or []
    partitioned = partition_warnings(warnings)
    deterministic = partitioned["deterministic"]
    ambiguous = partitioned["ambiguous"]

    if not warnings:
        return {
            "record_id": record_id,
            "action": "noop",
            "reason": "no_compliance_warnings",
            "deterministic_findings": [],
            "ambiguous_warnings": [],
        }

    if not deterministic:
        return {
            "record_id": record_id,
            "action": "agent_review",
            "reason": "no_deterministic_warnings_matched",
            "deterministic_findings": [],
            "ambiguous_warnings": ambiguous,
        }

    action = "remediate" if not ambiguous else "partial_remediate"
    return {
        "record_id": record_id,
        "action": action,
        "reason": "deterministic_whitelist_match",
        "deterministic_findings": deterministic,
        "ambiguous_warnings": ambiguous,
    }


# ---------------------------------------------------------------------------
# Idempotency guard (AC-4): a document already at `compliant` maturity (or
# with zero compliance_warnings) is always a no-op -- never re-patched.
# ---------------------------------------------------------------------------

COMPLIANT_MATURITY_STATE = "compliant"
RAW_MATURITY_STATE = "raw"


def is_already_compliant(document: Dict[str, Any]) -> bool:
    maturity = str(
        document.get("document_maturity_state") or document.get("maturity_state") or ""
    ).lower()
    warnings = document.get("compliance_warnings") or []
    return maturity == COMPLIANT_MATURITY_STATE or not warnings


# ---------------------------------------------------------------------------
# io-approval ramp -- verbatim pattern reuse from FTR-106 / ENC-TSK-K03
# (unlearning_core.py: IO_APPROVAL_RUNS / mutation_allowed / is_dry_run).
# ---------------------------------------------------------------------------

GDMP_DRY_RUN = os.environ.get("GDMP_DRY_RUN", "1").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
GDMP_MUTATION_ENABLED = os.environ.get("GDMP_MUTATION_ENABLED", "0").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)

try:
    GDMP_IO_APPROVAL_RUNS = int(os.environ.get("GDMP_IO_APPROVAL_RUNS", "3"))
except (TypeError, ValueError):
    GDMP_IO_APPROVAL_RUNS = 3


def is_dry_run(event: Optional[Dict[str, Any]] = None) -> bool:
    if isinstance(event, dict) and "dry_run" in event:
        return bool(event.get("dry_run"))
    return GDMP_DRY_RUN


def io_approval_ramp_active(run_count: int) -> bool:
    """True while live runs are still in the report-only ramp."""
    return run_count < GDMP_IO_APPROVAL_RUNS


def mutation_allowed(
    *,
    run_count: int,
    dry_run: bool,
    mutation_enabled: bool = GDMP_MUTATION_ENABLED,
) -> bool:
    if dry_run or not mutation_enabled:
        return False
    return not io_approval_ramp_active(run_count)


def is_hard_disabled(env: Dict[str, str]) -> bool:
    """CEE_GDMP_HARD_DISABLED kill switch -- mandatory before first scheduled
    run, mirroring CEE_HARD_DISABLED (K41) / UNLEARNING_MUTATION_ENABLED (K03)
    sibling convention. Any of "1"/"true"/"yes" (case-insensitive) disables.
    """
    val = str(env.get("CEE_GDMP_HARD_DISABLED", "0")).strip().lower()
    return val in ("1", "true", "yes")


def build_candidate_report_body(
    project_id: str,
    plans: Sequence[Dict[str, Any]],
    *,
    run_count: int,
    dry_run: bool,
    mutation_enabled: bool,
) -> str:
    """Human-readable candidate report -- mirrors
    unlearning_core.build_candidate_report_body's shape for consistency
    across the two io-approval-ramp Lambdas in this repo.
    """
    remediate_count = sum(1 for p in plans if p["action"] in ("remediate", "partial_remediate"))
    review_count = sum(1 for p in plans if p["action"] == "agent_review")
    lines = [
        f"# GDMP Stage-1 remediation candidate report — {project_id}",
        "",
        f"- run_count: {run_count}",
        f"- dry_run: {dry_run}",
        f"- mutation_enabled: {mutation_enabled}",
        f"- io_approval_ramp_active: {io_approval_ramp_active(run_count)}",
        f"- candidates_for_auto_remediation: {remediate_count}",
        f"- candidates_requiring_agent_review: {review_count}",
        "",
        "## Candidates",
        "",
    ]
    if not plans:
        lines.append("_No raw documents with compliance_warnings identified._")
    else:
        for p in plans:
            lines.append(
                f"- `{p.get('record_id')}` — action={p.get('action')} "
                f"deterministic={len(p.get('deterministic_findings', []))} "
                f"ambiguous={len(p.get('ambiguous_warnings', []))}"
            )
    return "\n".join(lines) + "\n"
