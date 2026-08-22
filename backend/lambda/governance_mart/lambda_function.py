"""Governance analytics mart -- scheduled full-refresh job.

BRD B3-R3 (DVP-TSK-649). Invoked by an EventBridge **schedule** (daily
minimum), never by a tracker mutation. The handler is deliberately thin: all
of the contract lives in ``mart_schema`` (the declaration), ``mart_source``
(the read), ``mart_project`` (the grain), and ``mart_refresh`` (the path), so
the same code serves the schedule and the operator CLI at
``tools/governance_mart_refresh.py``.

Event shape (all fields optional -- a bare EventBridge scheduled event is the
normal case and needs none of them)::

    {
      "tables":   ["dim_record", ...],   # subset, for targeted re-registration
      "last_day": "2026-08-07",          # pin the daily-grain upper bound
      "dry_run":  false                  # project and count, write nothing
    }

Returns the ``RefreshResult`` summary: per-table row, byte, and file counts
plus the shared write timestamp. A non-zero ``file_count`` above 1 on any
table is the B6-R2 full-refresh violation signal and is surfaced rather than
swallowed.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import date, datetime, timezone

from mart_refresh import refresh_mart

LOGGER = logging.getLogger()
LOGGER.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


def _parse_last_day(value):
    if not value:
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    return datetime.strptime(str(value)[:10], "%Y-%m-%d").date()


def lambda_handler(event, context):  # noqa: ANN001 - AWS signature
    event = event or {}
    tables = event.get("tables") or None
    dry_run = bool(event.get("dry_run"))
    last_day = _parse_last_day(event.get("last_day"))

    try:
        result = refresh_mart(tables=tables, last_day=last_day, dry_run=dry_run)
    except Exception:
        # Let the invocation FAIL loudly. A refresh that swallows its own error
        # and returns 200 is exactly the silent-stop failure mode this job was
        # built to make impossible: the daily series must stop drawing AND the
        # alarm must fire, not one without the other.
        LOGGER.exception("[ERROR] governance mart refresh failed")
        raise

    summary = result.as_dict()
    violations = [entry["table"] for entry in summary["tables"] if entry.get("files", 1) > 1]
    if violations:
        LOGGER.error(
            "[ERROR] full-refresh violation: %s hold more than one object. "
            "File count must track data size, never write count (DOC-1E1EC5B7CE02).",
            ", ".join(violations),
        )
    summary["full_refresh_violations"] = violations

    LOGGER.info("[SUCCESS] %s", json.dumps(summary, default=str))
    return {"statusCode": 200, "body": summary}
