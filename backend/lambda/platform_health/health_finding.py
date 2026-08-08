"""The finding: what a check produces, and the identity that makes it dedupable.

DVP-TSK-665 / DVP-PLN-001.

Every one of the nine checks returns a list of ``Finding`` objects and nothing
else. The handler does not know what any check means; it knows how to serialise
a finding to the health surface and how to file one as a governed issue. That
keeps a new check a matter of writing a predicate, not of extending the
plumbing.

Signature dedup is not optional decoration. ``env_drift_auditor`` learned this
the expensive way: one persistent finding, filed unconditionally on every
scheduled run, produced eleven byte-identical P0s (ENC-ISS-369..379) before the
signature scheme in ENC-TSK-H10 was added. A daily health monitor with nine
checks has the same shape and would produce the same storm, so the identity is
built in here from the start rather than retrofitted after the first flood.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from health_contract import (
    CHECK_PRIORITY,
    DEFAULT_CHECK_PRIORITY,
    ISSUE_FILING_SEVERITIES,
    SEVERITY_BREACH,
    SEVERITY_ERROR,
    SEVERITY_OK,
    SEVERITY_WARNING,
)

#: Prefix on an auto-filed issue title. Matches the `[auto-drift]` convention
#: env_drift_auditor established so the two auditors' output reads as one family.
TITLE_PREFIX = "[auto-health]"

#: Ordering used to reduce many findings to one overall status.
_SEVERITY_RANK = {
    SEVERITY_OK: 0,
    SEVERITY_WARNING: 1,
    SEVERITY_ERROR: 2,
    SEVERITY_BREACH: 3,
}


@dataclass
class Finding:
    """One observation from one check about one subject.

    ``check`` is the check id (``check_1_freshness``). ``subject`` is the thing
    observed -- a Trino identifier, a crawler name, a container name. Together
    with ``kind`` they form the signature, so a finding keeps ONE identity across
    runs for as long as the condition persists, and gets a NEW one when the
    condition changes shape.

    ``observed`` and ``expected`` carry the numbers. They are what makes a
    finding checkable by a reader rather than merely assertive: the evidence on
    the filed issue quotes both, alongside ``steps_to_duplicate`` that reproduce
    the measurement from a shell.
    """

    check: str
    subject: str
    severity: str
    kind: str
    summary: str
    observed: Dict[str, Any] = field(default_factory=dict)
    expected: Dict[str, Any] = field(default_factory=dict)
    steps_to_duplicate: Sequence[str] = ()
    remediation: str = ""
    references: Sequence[str] = ()

    @property
    def signature(self) -> str:
        """Stable identity of (check, subject, kind). Not of the MEASUREMENT.

        Deliberately excludes ``observed``: a table that is 27 hours stale on
        Monday and 51 hours stale on Tuesday is the SAME unresolved finding, and
        must bump one record rather than open a second. A finding whose kind
        changes -- ``stale`` becoming ``missing_data`` -- is genuinely a
        different condition and correctly gets a new signature.
        """
        payload = "|".join((self.check, self.subject, self.kind))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    @property
    def sig_token(self) -> str:
        """The signature as it appears in an issue title, for title-match dedup."""
        return "[sig:%s]" % self.signature

    @property
    def files_issue(self) -> bool:
        return self.severity in ISSUE_FILING_SEVERITIES

    @property
    def priority(self) -> str:
        return CHECK_PRIORITY.get(self.check, DEFAULT_CHECK_PRIORITY)

    def title(self) -> str:
        return "%s %s: %s %s" % (TITLE_PREFIX, self.check, self.summary, self.sig_token)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check": self.check,
            "subject": self.subject,
            "severity": self.severity,
            "kind": self.kind,
            "summary": self.summary,
            "observed": self.observed,
            "expected": self.expected,
            "signature": self.signature,
            "steps_to_duplicate": list(self.steps_to_duplicate),
            "remediation": self.remediation,
            "references": list(self.references),
        }


@dataclass
class CheckResult:
    """One check's whole output: its findings plus what it managed to look at.

    ``subjects_examined`` matters as much as ``findings``. A check that returned
    zero findings because it examined zero subjects is indistinguishable from a
    healthy estate unless it says how many it looked at -- and that
    indistinguishability is precisely how a monitor comes to report green
    forever. ``error`` is set when the check could not run at all, which is a
    third state and never silently collapsed into "healthy".
    """

    check: str
    title: str
    subjects_examined: int = 0
    findings: List[Finding] = field(default_factory=list)
    detail: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def severity(self) -> str:
        if self.error:
            return SEVERITY_ERROR
        if not self.findings:
            return SEVERITY_OK
        return max((f.severity for f in self.findings), key=lambda s: _SEVERITY_RANK.get(s, 0))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check": self.check,
            "title": self.title,
            "severity": self.severity,
            "subjects_examined": self.subjects_examined,
            "finding_count": len(self.findings),
            "breach_count": sum(1 for f in self.findings if f.severity == SEVERITY_BREACH),
            "findings": [f.to_dict() for f in self.findings],
            "detail": self.detail,
            "error": self.error,
        }


def overall_severity(results: Sequence[CheckResult]) -> str:
    if not results:
        return SEVERITY_ERROR
    return max((r.severity for r in results), key=lambda s: _SEVERITY_RANK.get(s, 0))


def issue_body(finding: Finding, run_id: str, observed_at: str) -> Dict[str, Any]:
    """The governed issue payload for one breaching finding.

    Shaped for `POST {TRACKER_API_BASE}/{project}/issue`. ``hypothesis`` and
    ``technical_notes`` are both populated because the tracker requires at least
    one, and ``evidence[].steps_to_duplicate`` is required on every entry.
    """
    return {
        "title": finding.title(),
        "priority": finding.priority,
        "status": "open",
        "category": "risk",
        "severity": "high" if finding.priority in ("P0", "P1") else "medium",
        "hypothesis": (
            "B6-R2 platform health monitor check %s observed %s on %s at %s. "
            "Observed %s against declared %s. Signature %s; auditor run_id=%s."
            % (
                finding.check,
                finding.kind,
                finding.subject,
                observed_at,
                json.dumps(finding.observed, sort_keys=True, default=str),
                json.dumps(finding.expected, sort_keys=True, default=str),
                finding.signature,
                run_id,
            )
        ),
        "location_hint": "backend/lambda/platform_health/",
        "technical_notes": finding.remediation
        or "See the check's module docstring in backend/lambda/platform_health/.",
        "evidence": [
            {
                "description": "%s -- %s" % (finding.summary, finding.kind),
                "observed_by": "platform-health-monitor",
                "timestamp": observed_at,
                "steps_to_duplicate": list(finding.steps_to_duplicate)
                or ["Invoke devops-platform-health and read the returned findings array."],
                "observed": finding.observed,
                "expected": finding.expected,
                "signature": finding.signature,
                "references": list(finding.references),
                "auditor_run_id": run_id,
            }
        ],
    }
