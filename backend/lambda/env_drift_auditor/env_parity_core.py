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

Pure module: no environment reads, no AWS calls, no side effects at import time
(unlike lambda_function.py, which reads os.environ at import) — so it is safe to
import from CLI tools and unit tests.
"""

from __future__ import annotations

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
