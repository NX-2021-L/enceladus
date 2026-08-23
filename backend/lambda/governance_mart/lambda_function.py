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

ENC-TSK-O80: on the gamma path (GovernanceMartScheduleGamma, 02-compute.yaml)
the trigger is an EventBridge **Scheduler** schedule with a RetryPolicy and a
DLQ, not a bare Rule. Its Target.Input pins ``last_day`` to the
``<aws.scheduler.scheduled-time>`` context attribute -- an ISO-8601 string
Scheduler substitutes with the schedule's INTENDED fire time, constant across
every automatic retry of that firing. ``_parse_last_day`` truncates that to
its leading ``YYYY-MM-DD``. Without this, a retry firing after midnight UTC
would resolve ``last_day`` from wall-clock ``datetime.now()`` instead and
silently rebuild the WRONG day's grain under the failed run's schedule slot --
still landing at the mart's one deterministic per-table key
(``DOC-1E1EC5B7CE02``, ``enceladus_shared.warehouse_registration``), so never
a duplicate object, but the wrong day's content. Retries are new precisely
because Scheduler makes them automatic; a plain Rule target never offered a
configurable RetryPolicy to trigger this failure mode in the first place.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import date, datetime, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from mart_refresh import refresh_mart

LOGGER = logging.getLogger()
LOGGER.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


def _parse_last_day(value):
    if not value:
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    return datetime.strptime(str(value)[:10], "%Y-%m-%d").date()


HEARTBEAT_NAMESPACE = "Enceladus/GovernanceMart"
HEARTBEAT_METRIC = "MartLastSuccess"


def _emit_heartbeat(function_name):
    """Publish the ENC-TSK-O81 dead-man's-switch heartbeat. SUCCESS PATH ONLY.

    This is the only signal that can catch a job which NEVER RAN. An error-rate
    alarm and a failure metric structurally cannot: a run that never happens
    produces no log line and no exit code, so there is nothing for them to
    measure. The paired alarm therefore sets ``TreatMissingData: breaching`` --
    ABSENCE is the alarm condition, which is the whole point.

    Deliberately NOT called from a ``finally`` block, NOT called before
    registration has completed, and NOT called on the dry-run or
    full-refresh-violation paths. A heartbeat that can fire when the work did
    not actually land rebuilds precisely the self-fulfilling-signal defect
    ENC-ISS-665 was filed for -- a freshness signal that reports health because
    it was asked, rather than because the work happened.

    A failure to PUBLISH is logged and swallowed rather than raised. The refresh
    genuinely succeeded by this point, and turning a telemetry fault into a data
    outage would be the wrong trade. The failure mode is safe in the right
    direction: no datapoint means the alarm breaches, which is a false alarm
    rather than a silent stop.
    """
    try:
        boto3.client("cloudwatch").put_metric_data(
            Namespace=HEARTBEAT_NAMESPACE,
            MetricData=[
                {
                    "MetricName": HEARTBEAT_METRIC,
                    "Dimensions": [{"Name": "FunctionName", "Value": function_name}],
                    "Value": 1,
                    "Unit": "Count",
                    "Timestamp": datetime.now(timezone.utc),
                }
            ],
        )
        LOGGER.info(
            "[INFO] heartbeat published: %s/%s FunctionName=%s",
            HEARTBEAT_NAMESPACE,
            HEARTBEAT_METRIC,
            function_name,
        )
    except (BotoCoreError, ClientError):
        LOGGER.exception(
            "[ERROR] heartbeat publish FAILED for %s. The refresh itself SUCCEEDED; "
            "this is a telemetry fault, not a data fault. The missing-data alarm will "
            "breach, which is a false alarm rather than a silent stop -- fail-safe in "
            "the correct direction.",
            function_name,
        )


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

    # ENC-TSK-O81 dead-man's-switch. Gated on a genuinely clean run: a dry run
    # wrote nothing, and a full-refresh violation means the objects that landed
    # are the wrong SHAPE. Neither is a day the daily series should count as
    # healthy, so neither earns a heartbeat.
    if not dry_run and not violations:
        _emit_heartbeat(getattr(context, "function_name", None) or os.environ.get("AWS_LAMBDA_FUNCTION_NAME", "unknown"))

    return {"statusCode": 200, "body": summary}
