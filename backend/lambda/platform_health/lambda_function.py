"""B6-R2 platform health monitor -- scheduled, source-agnostic.

DVP-TSK-665 / DVP-PLN-001. Invoked by an EventBridge **schedule**, never by a
mutation event. Each run is a complete observation of current state, so there is
nothing for an incremental trigger to maintain.

The handler is deliberately thin. It knows three verbs -- run the checks, write
the surface, emit the breaches -- and nothing about what any individual check
means. Each check returns ``CheckResult`` objects and the handler serialises
them; adding a tenth check is a matter of writing a predicate and appending one
line to ``run_checks``.

Event shape (all optional; a bare scheduled event needs none of it)::

    {
      "checks":  ["check_1_freshness", ...],   # subset, for targeted runs
      "dry_run": false,                        # observe and report, file nothing
      "publish": true                          # write the surface + T2 tables
    }

A check that raises does NOT abort the run. Nine independent observations of a
live estate will eventually have one of them fail on a transient AWS error, and
a monitor that reports nothing because its seventh check timed out has converted
a partial signal into no signal. The failure is captured on that check's
``error`` field, which is a THIRD state distinct from both healthy and
breaching, and the surface records it as such.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence

import boto3

import health_issues
import health_surface
from checks_platform import (
    check_adhoc_quota,
    check_container_health,
    check_cpu_credit,
    check_dependency_drift,
)
from checks_contract import check_crawlers, check_namespace_isolation, check_storage_format
from checks_freshness import check_freshness, check_full_refresh
from health_finding import CheckResult, overall_severity

LOGGER = logging.getLogger()
LOGGER.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

REGION = os.environ.get("AWS_REGION", "us-west-2")
PUBLISH_TABLES = os.environ.get("PUBLISH_TABLES", "true").lower() == "true"

_CLIENTS: Dict[str, Any] = {}


def client(service: str, region: Optional[str] = None):
    """Cached boto3 client. Region is part of the key -- check 2 is multi-region."""
    key = "%s@%s" % (service, region or REGION)
    if key not in _CLIENTS:
        _CLIENTS[key] = boto3.client(service, region_name=region or REGION)
    return _CLIENTS[key]


def _guarded(check_id: str, title: str, fn: Callable[[], CheckResult]) -> CheckResult:
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001
        LOGGER.exception("[ERROR] check %s failed to run", check_id)
        return CheckResult(check=check_id, title=title, error="%s: %s" % (type(exc).__name__, exc))


def run_checks(
    now: Optional[datetime] = None, selected: Optional[Sequence[str]] = None
) -> List[CheckResult]:
    now = now or datetime.now(timezone.utc)
    wanted = set(selected) if selected else None

    def want(check_id: str) -> bool:
        return wanted is None or check_id in wanted

    s3 = client("s3")
    glue = client("glue")

    results: List[CheckResult] = []
    if want("check_1_freshness"):
        results.append(
            _guarded(
                "check_1_freshness",
                "Freshness of every registered warehouse table against its declared SLA",
                lambda: check_freshness(s3, glue, now=now),
            )
        )
    if want("check_2_crawler"):
        results.append(
            _guarded(
                "check_2_crawler",
                "Glue crawlers across every scanned region, against the crawler prohibition",
                # The client FACTORY is passed, not a client: check 2 is the one
                # check that must look outside the home region, and handing it a
                # single pre-bound client is exactly how it would come to report
                # a clean estate it never looked at.
                lambda: check_crawlers(lambda region: client("glue", region)),
            )
        )
    if want("check_3_namespace_isolation"):
        results.append(
            _guarded(
                "check_3_namespace_isolation",
                "Tables in a governed namespace without a registered export job",
                lambda: check_namespace_isolation(s3, glue),
            )
        )
    if want("check_4_storage_format"):
        results.append(
            _guarded(
                "check_4_storage_format",
                "Storage format of every table in a governed namespace",
                lambda: check_storage_format(glue),
            )
        )
    if want("check_5_full_refresh"):
        results.append(
            _guarded(
                "check_5_full_refresh",
                "Warehouse file counts against full-refresh semantics",
                lambda: check_full_refresh(s3),
            )
        )
    if want("check_6_container_health"):
        results.append(
            _guarded(
                "check_6_container_health",
                "Trino and Superset container health, with OOM read from the kernel log",
                lambda: check_container_health(client("ssm"), now=now),
            )
        )
    if want("check_7_adhoc_quota"):
        results.append(
            _guarded(
                "check_7_adhoc_quota",
                "Ad-hoc namespace size and table count against quota",
                lambda: check_adhoc_quota(s3, glue),
            )
        )
    if want("check_8_cpu_credit"):
        results.append(
            _guarded(
                "check_8_cpu_credit",
                "CPUCreditBalance while the host is burstable",
                lambda: check_cpu_credit(client("cloudwatch"), client("ec2"), now=now),
            )
        )
    if want("check_9_dependency_drift"):
        results.append(
            _guarded(
                "check_9_dependency_drift",
                "Declared IAM and configuration dependency surface against live AWS",
                lambda: check_dependency_drift(client("iam"), client("ec2")),
            )
        )
    return results


def lambda_handler(event, context):  # noqa: ANN001 - AWS signature
    event = event or {}
    run_id = getattr(context, "aws_request_id", "manual-run")
    now = datetime.now(timezone.utc)
    observed_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    dry_run = bool(event.get("dry_run"))
    publish = bool(event.get("publish", PUBLISH_TABLES))

    results = run_checks(now=now, selected=event.get("checks"))
    findings = [f for r in results for f in r.findings]

    emissions = health_issues.emit(findings, run_id, observed_at, dry_run=dry_run)

    snapshot = health_surface.build_snapshot(results, run_id, observed_at, emissions)
    surface: Dict[str, Any] = {}
    if publish and not dry_run:
        s3 = client("s3")
        try:
            surface["snapshot_keys"] = health_surface.write_snapshot(s3, snapshot)
            history = health_surface.load_history(s3)
            surface["tables"] = health_surface.publish_tables(
                s3, client("glue"), history, write_timestamp=now
            )
        except Exception as exc:  # noqa: BLE001
            # A surface write failure must not hide the observations that were
            # already made -- they are still returned and still logged.
            LOGGER.exception("[ERROR] health surface publication failed")
            surface["error"] = "%s: %s" % (type(exc).__name__, exc)

    summary = {
        "run_id": run_id,
        "observed_at": observed_at,
        "overall_severity": overall_severity(results),
        "checks_run": len(results),
        "checks_errored": sum(1 for r in results if r.error),
        "finding_count": len(findings),
        "breach_count": sum(1 for f in findings if f.files_issue),
        "issues_emitted": emissions,
        "surface": surface,
        "checks": [
            {
                "check": r.check,
                "severity": r.severity,
                "subjects_examined": r.subjects_examined,
                "findings": len(r.findings),
                "error": r.error,
            }
            for r in results
        ],
    }
    LOGGER.info("[SUCCESS] %s", json.dumps(summary, default=str))
    return {"statusCode": 200, "body": summary, "snapshot": snapshot}
