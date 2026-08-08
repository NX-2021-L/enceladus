"""File a breaching finding as a governed issue record -- idempotently.

DVP-TSK-665 / DVP-PLN-001.

The transport and the dedup contract are lifted deliberately from
``env_drift_auditor`` (ENC-TSK-H10 / ENC-TSK-J30) rather than reinvented: same
internal-key tracker API, same open-issue scan, same fail-open-to-filing rule
when the dedup query itself errors. Two auditors that file issues into the same
tracker should file them the same way.

The one rule worth restating, because it is the one that was learned by being
broken: **a persistent finding is filed ONCE and bumped thereafter.** There is
no tracker-side guard collapsing identical titles. Filing unconditionally on a
schedule does not produce a reminder, it produces a flood, and a flood is
indistinguishable from noise at exactly the moment the finding matters.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Sequence, Tuple

from health_finding import Finding, issue_body

LOGGER = logging.getLogger(__name__)

TRACKER_API_BASE = os.environ.get(
    "TRACKER_API_BASE",
    "https://8nkzqkmxqc.execute-api.us-west-2.amazonaws.com/api/v1/tracker",
)
ISSUE_PROJECT_ID = os.environ.get("ISSUE_PROJECT_ID", "devops")

#: 200 per page * 10 pages bounds the daily dedup scan well above any real
#: open-issue backlog.
_MAX_ISSUE_PAGES = 10
_HTTP_TIMEOUT = 20


def _api_key() -> str:
    key = os.environ.get("COORDINATION_INTERNAL_API_KEY", "")
    if not key:
        raise RuntimeError(
            "COORDINATION_INTERNAL_API_KEY is not set. The monitor cannot file a "
            "governed issue without it, and a health monitor that silently stops "
            "filing is worse than one that fails loudly."
        )
    return key


def _request(url: str, method: str, body: Optional[Dict[str, Any]] = None) -> Tuple[int, Any]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"X-Coordination-Internal-Key": _api_key()}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, method=method, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
            raw = resp.read()
            try:
                return resp.status, json.loads(raw)
            except ValueError:
                return resp.status, raw.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")


def fetch_open_issues() -> List[Dict[str, Any]]:
    """Every OPEN issue in the project, paginated. Raises on transport failure."""
    issues: List[Dict[str, Any]] = []
    cursor = ""
    for _ in range(_MAX_ISSUE_PAGES):
        url = "%s/%s?type=issue&status=open&page_size=200" % (TRACKER_API_BASE, ISSUE_PROJECT_ID)
        if cursor:
            url += "&next_cursor=" + urllib.parse.quote(cursor, safe="")
        status, payload = _request(url, "GET")
        if status >= 400 or not isinstance(payload, dict):
            raise RuntimeError("open-issue query returned %s: %s" % (status, payload))
        issues.extend(payload.get("records", []))
        cursor = payload.get("next_cursor", "")
        if not cursor:
            break
    return issues


def find_open_issue_for(issues: Sequence[Dict[str, Any]], finding: Finding) -> Optional[str]:
    """The already-open issue carrying this finding's signature, if any.

    Matches on the signature token in the title. The token is generated from
    (check, subject, kind) only, so a worsening measurement bumps the same
    record and a genuinely different condition opens a new one.
    """
    token = finding.sig_token
    for record in issues:
        title = record.get("title") or ""
        if token in title:
            return record.get("item_id") or record.get("record_id") or ""
    return None


def bump_issue(issue_id: str, finding: Finding, run_id: str, observed_at: str) -> Dict[str, Any]:
    """Append a worklog to an open issue rather than filing a duplicate."""
    body = {
        "description": (
            "[auto-health] %s still breaching on %s at %s (run_id=%s). Observed %s. "
            "Unresolved since this issue was filed; bumping instead of re-filing "
            "(signature %s)."
            % (
                finding.check,
                finding.subject,
                observed_at,
                run_id,
                json.dumps(finding.observed, sort_keys=True, default=str),
                finding.signature,
            )
        ),
        "write_source": {"provider": "platform-health-monitor"},
    }
    url = "%s/%s/issue/%s/log" % (TRACKER_API_BASE, ISSUE_PROJECT_ID, issue_id)
    status, payload = _request(url, "POST", body)
    result = {"action": "bumped", "issue_id": issue_id, "status": status,
              "signature": finding.signature}
    if status >= 400:
        result["error"] = payload
    return result


def file_issue(finding: Finding, run_id: str, observed_at: str) -> Dict[str, Any]:
    """File a NEW governed issue for this finding."""
    url = "%s/%s/issue" % (TRACKER_API_BASE, ISSUE_PROJECT_ID)
    status, payload = _request(url, "POST", issue_body(finding, run_id, observed_at))
    result: Dict[str, Any] = {"action": "filed", "status": status,
                              "signature": finding.signature}
    if isinstance(payload, dict):
        record = payload.get("record") or payload
        result["issue_id"] = record.get("item_id") or record.get("record_id") or ""
    if status >= 400:
        result["error"] = payload
    return result


def emit(
    findings: Sequence[Finding],
    run_id: str,
    observed_at: str,
    dry_run: bool = False,
) -> List[Dict[str, Any]]:
    """File or bump one governed issue per breaching finding.

    The open-issue scan happens ONCE for the whole batch, not per finding: nine
    checks against a live estate can breach on many subjects at once, and a
    per-finding scan would multiply a full paginated listing by the size of the
    outage.

    If the scan itself fails the batch fails OPEN -- every finding is filed
    without dedup. A duplicated issue is recoverable; a dropped breach is the
    condition this whole monitor exists to prevent.
    """
    emissions: List[Dict[str, Any]] = []
    breaching = [f for f in findings if f.files_issue]
    if not breaching:
        return emissions

    if dry_run:
        return [
            {"action": "dry_run", "signature": f.signature, "title": f.title()}
            for f in breaching
        ]

    try:
        open_issues = fetch_open_issues()
        dedup_ok = True
    except Exception as exc:  # noqa: BLE001
        LOGGER.exception("open-issue dedup query failed; failing OPEN to filing")
        open_issues = []
        dedup_ok = False

    for finding in breaching:
        existing = find_open_issue_for(open_issues, finding) if dedup_ok else None
        try:
            if existing:
                emissions.append(bump_issue(existing, finding, run_id, observed_at))
            else:
                emission = file_issue(finding, run_id, observed_at)
                if not dedup_ok:
                    emission["dedup_skipped"] = True
                emissions.append(emission)
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("issue emission failed for %s", finding.signature)
            emissions.append(
                {"action": "failed", "signature": finding.signature, "error": str(exc)}
            )
    return emissions
