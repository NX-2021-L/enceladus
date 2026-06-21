"""env_parity_core — shared environment-variable comparison primitives.

ENC-TSK-H19 (ENC-PLN-048 Objective 2, parent ENC-TSK-H12, feature ENC-FTR-102).

This is the SINGLE source of env-comparison logic, imported by BOTH:

  * env_drift_auditor/lambda_function.py   — post-deploy scan: required vars
    that are missing or placeholder on a LIVE Lambda.
  * tools/live_template_strip_detector.py  — pre-deploy scan: vars present LIVE
    but NOT set by the template-resolved env (the deploy would strip them — the
    H05/H09 incident signature).

ENC-TSK-H19 AC2 (no divergent second implementation): the placeholder set and
the missing/placeholder comparison that used to be inline in env_drift_auditor
now live here, so the pre-deploy detector reuses exactly the same primitives
rather than re-deriving them. Post-deploy and pre-deploy stay consistent by
construction.

ENC-TSK-H16 (ENC-PLN-048 Objective 1, parent ENC-TSK-H11): this module is also
the SINGLE interpreter of the env_drift_registry.json ``lambdas`` entry shape and
its per-var deploy-critical/advisory classification. Every consumer — the H17
resolver/diff, the H18 pre-deploy gate, the H19 strip detector, and the
post-deploy auditor — reads the registry through ``required_vars`` /
``classification_of`` here instead of re-deriving the shape, so the classification
has exactly one source of truth (AC2: "single source, no second copy"). Two entry
shapes are accepted per function:

  * dict (canonical, H16): ``{"VAR": "deploy-critical" | "advisory", ...}``
  * list (legacy):         ``["VAR", ...]`` — every var treated as deploy-critical
    (the fail-closed default).

Pure module: no environment reads, no AWS calls, no side effects at import time
(unlike lambda_function.py, which reads os.environ at import) — so it is safe to
import from CLI tools and unit tests.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Sequence

# Values that count as "not really set" (drift), independent of any registry.
# Mirrors the historical env_drift_auditor list so behavior is unchanged.
DEFAULT_PLACEHOLDERS: List[str] = ["", "CHANGE_ME", "TODO", "REPLACE_", "REPLACE_WITH_", "null", "None"]


def build_placeholders(policy: Optional[Dict[str, Any]] = None) -> set:
    """Build the placeholder set: registry ``_policy`` extras + module defaults.

    ``policy`` is the env_drift_registry.json ``_policy`` block (or None).
    """
    extra = list((policy or {}).get("placeholder_values_that_count_as_drift", []))
    return set(extra + DEFAULT_PLACEHOLDERS)


def is_placeholder(value: Optional[str], placeholders: set) -> bool:
    """True if ``value`` is a placeholder (drift). None is 'missing', not placeholder."""
    if value is None:
        return False
    return value in placeholders or value.startswith("REPLACE_")


def classify_required(
    required: Sequence[str],
    env: Dict[str, str],
    placeholders: set,
) -> List[Dict[str, Any]]:
    """Post-deploy comparison (env_drift_auditor): for each required var, flag it
    if missing or set to a placeholder value.

    Returns a list of drift rows ``[{"var": str, "reason": str}]`` — identical in
    shape and semantics to the pre-refactor env_drift_auditor inline logic.
    """
    drift: List[Dict[str, Any]] = []
    for var in required:
        val = env.get(var)
        if val is None:
            drift.append({"var": var, "reason": "missing"})
        elif is_placeholder(val, placeholders):
            drift.append({"var": var, "reason": f"placeholder value: {val!r}"})
    return drift


def live_only_vars(live_env: Dict[str, str], template_env: Dict[str, str]) -> List[str]:
    """Pre-deploy comparison (H19): variable names present in the LIVE env but NOT
    set by the template-resolved env.

    These are exactly the vars a CloudFormation deploy of the template would strip
    from the live function (because the template does not set them). Returned
    sorted for stable reporting. The template side must already have AWS::NoValue
    /!If resolution applied (see tools/cfn_env_resolver.py) so a conditionally
    -unset var is not mistaken for a live-only var.
    """
    return sorted(set(live_env or {}) - set(template_env or {}))


# ---------------------------------------------------------------------------
# Registry entry shape + per-var classification (ENC-TSK-H16)
# ---------------------------------------------------------------------------
# A function's env_drift_registry.json "lambdas" entry declares its required env
# vars. H16 adds a per-var classification while keeping the legacy flat-list form
# working. These helpers are the ONLY place that interprets the entry shape, so
# the resolver, gate, strip detector, and auditor never re-derive it (AC2).

DEPLOY_CRITICAL = "deploy-critical"
ADVISORY = "advisory"
VALID_CLASSIFICATIONS = (DEPLOY_CRITICAL, ADVISORY)
# Anything not explicitly classified (legacy list entry, unknown value) is
# treated as deploy-critical: the gate fails closed and the auditor files a P0.
DEFAULT_CLASSIFICATION = DEPLOY_CRITICAL


def required_vars(entry: Any) -> List[str]:
    """All required env-var names for a function's registry entry.

    Accepts the canonical dict form ``{"VAR": classification}`` (returns its keys)
    or the legacy list form ``["VAR", ...]``. ``None`` (no entry) yields ``[]``.
    """
    if entry is None:
        return []
    if isinstance(entry, dict):
        return list(entry.keys())
    if isinstance(entry, (list, tuple)):
        return list(entry)
    raise TypeError(f"unsupported registry entry type: {type(entry).__name__}")


def classification_of(entry: Any, var: str) -> str:
    """Classification of a single var: ``deploy-critical`` or ``advisory``.

    Legacy list entries, unknown classification strings, and vars absent from a
    dict entry all resolve to ``deploy-critical`` (the fail-closed default).
    """
    if isinstance(entry, dict):
        value = entry.get(var, DEFAULT_CLASSIFICATION)
        return value if value in VALID_CLASSIFICATIONS else DEFAULT_CLASSIFICATION
    return DEFAULT_CLASSIFICATION


def is_deploy_critical(entry: Any, var: str) -> bool:
    """True if ``var`` is deploy-critical for this entry (gate fails closed)."""
    return classification_of(entry, var) == DEPLOY_CRITICAL


def critical_vars(entry: Any) -> List[str]:
    """Required vars classified deploy-critical (gate FAIL / auditor P0 set)."""
    return [v for v in required_vars(entry) if is_deploy_critical(entry, v)]


def advisory_vars(entry: Any) -> List[str]:
    """Required vars classified advisory (gate WARN / auditor report-only set)."""
    return [v for v in required_vars(entry) if not is_deploy_critical(entry, v)]


def classification_map(entry: Any) -> Dict[str, str]:
    """``{var: classification}`` for every required var in the entry."""
    return {v: classification_of(entry, v) for v in required_vars(entry)}


# ---------------------------------------------------------------------------
# Drift-issue dedup signature (ENC-TSK-H10)
# ---------------------------------------------------------------------------
# env_drift_auditor runs hourly. Before H10 it POSTed a NEW P0 issue every run
# for the SAME unresolved drift — ENC-ISS-369..379 were 11 byte-identical P0s,
# one per hour, for ONE finding — because it assumed a tracker-side dedup guard
# that does not exist. These helpers give each finding a stable identity so the
# auditor can recognize an already-open issue and bump it instead of re-filing.
# The signature is the dedup key AC-1 requires; it travels in the issue TITLE via
# sig_token() because the tracker create API persists only a fixed field
# whitelist (an arbitrary top-level field would be silently dropped) and the
# title round-trips through the create -> list path the auditor queries.


def drift_signature(fn_name: str, missing_vars: Sequence[str]) -> str:
    """Stable content hash identifying a drift finding by (lambda, missing-var set).

    Order- and duplicate-independent: built from the sorted unique var set, so the
    same persistent drift always hashes to the same value regardless of the order
    ``classify_required`` happened to emit the rows in (the ``frozenset(missing_vars)``
    dedup key from the ENC-TSK-H10 design). 12 hex chars (48 bits) is ample to keep
    the handful of live (function, missing-var-set) findings distinct without
    bloating the issue title.
    """
    canonical = fn_name + "\n" + "\n".join(sorted(set(missing_vars)))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]


def sig_token(signature: str) -> str:
    """The machine-matchable marker embedded in a drift issue's title.

    Carried in the title (a whitelisted, always-returned field) so a later auditor
    run can recognize its own prior issue from a plain ``type=issue&status=open``
    listing without depending on any custom-field round-trip.
    """
    return f"[sig:{signature}]"


def find_signature_match(open_issues: Sequence[Dict[str, Any]], signature: str) -> Optional[str]:
    """Return the bare id of the first OPEN issue carrying ``signature``, else None.

    Pure decision half of the auditor's idempotency (ENC-TSK-H10 AC-2): given the
    records a ``type=issue&status=open`` query returned, find one whose title carries
    ``sig_token(signature)``. The auditor bumps that issue rather than filing a new
    one. Prefers ``item_id`` (the bare ENC-ISS-NNN the ``/log`` route path wants) and
    falls back to the segment after ``#`` in ``record_id``.
    """
    token = sig_token(signature)
    for issue in open_issues:
        if token in str(issue.get("title", "")):
            bare = issue.get("item_id") or issue.get("id")
            if not bare:
                rid = str(issue.get("record_id", ""))
                bare = rid.split("#", 1)[1] if "#" in rid else rid
            if bare:
                return bare
    return None
