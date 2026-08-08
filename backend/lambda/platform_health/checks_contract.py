"""Checks 2, 3 and 4 -- the enforcement arm of the warehouse contract.

DVP-TSK-695 / BRD B6-R2 / DVP-PLN-001. These three are the mechanical half of
obligations that until now existed only as prose: B2-R3 (no crawlers), B5-R4
(namespace isolation) and B2-R6 (Parquet).

CHECK 2 -- crawlers, IN EVERY REGION.

The region tuple is the part of this check that was paid for rather than
reasoned to. On 2026-08-07 the ten Glue crawlers in us-west-2 were deleted, and
a single-region sweep run the next morning would have reported a clean estate.
It would have been wrong: ``daily-data-crawler`` was still live in **us-west-1**
(database ``jds_scraper_db``, target ``s3://jds-scraper-output/structured/``,
``cron(0 17 * * ? *)``) and had run that same day. A crawler check that only
looks where crawlers were last deleted can only ever confirm its own prior.

So the check reports at two levels, and the difference matters:

  breach   a crawler whose S3 target overlaps a GOVERNED warehouse prefix.
           This is the DOC-5E35E14DAD05 violation outright -- a crawler
           inferring the schema of a governed T2 table, where the schema is
           supposed to be a declared value written by the export job's own code.
  warning  a crawler that exists at all, anywhere in the scanned regions.
           Not a violation on its own; ``jds_scraper_db`` is not a governed
           namespace and nothing here proposes deleting it. It is reported so
           that the estate cannot silently grow a crawler again, which is
           exactly what happened between the prohibition being written and
           anyone counting.

CHECK 3 -- a table in a governed namespace that no registered export job put
there. This is the isolation-breach detector: the thing that would catch an
errant upload landing in a project schema instead of quarantine. A governed
table's existence should be traceable to a registration record written by the
code path that wrote its data; a table with no such record arrived by some other
route, and "some other route" is the whole risk.

Legacy tables that predate the B2-R2 library are STILL REPORTED, at warning
rather than breach, against a dated baseline in ``health_contract``. That is
deliberately not an exemption: an allowlist that silences a finding teaches the
reader the finding does not exist. finance's 18 tables are a real, known gap and
they should stay visible as one.

CHECK 4 -- storage format. Parquet is declared, never inherited from a Trino
default, and the check reads the actual serde on the Glue table rather than the
``classification`` parameter, because classification is a hint a crawler writes
and the serde is what Trino actually uses to read bytes.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from health_contract import (
    CRAWLER_SCAN_REGIONS,
    GOVERNED_DATABASES,
    LEGACY_BASELINE_TAKEN_AT,
    LEGACY_UNREGISTERED_BASELINE,
    REQUIRED_CLASSIFICATION,
    REQUIRED_INPUT_FORMAT,
    REQUIRED_SERDE,
    SEVERITY_BREACH,
    SEVERITY_WARNING,
)
from checks_freshness import list_registered_tables
from health_finding import CheckResult, Finding

LOGGER = logging.getLogger(__name__)

CHECK_2 = "check_2_crawler"
CHECK_3 = "check_3_namespace_isolation"
CHECK_4 = "check_4_storage_format"


# ---------------------------------------------------------------------------
# Check 2 -- crawlers, in every region
# ---------------------------------------------------------------------------


def _governed_prefixes(databases: Dict[str, Dict[str, Any]]) -> List[str]:
    """The S3 URIs a crawler must never point at."""
    prefixes = []
    for spec in databases.values():
        bucket, project = spec["bucket"], spec["project"]
        if spec.get("tier") == "quarantine":
            prefixes.append("s3://%s/adhoc/" % bucket)
        else:
            prefixes.append("s3://%s/warehouse/%s/" % (bucket, project))
    return sorted(set(prefixes))


def _targets_governed_prefix(crawler: Dict[str, Any], prefixes: Sequence[str]) -> List[str]:
    """Governed prefixes this crawler's S3 targets overlap, in either direction.

    Overlap is checked BOTH ways on purpose. A crawler pointed at
    ``s3://bucket/warehouse/`` does not literally start with
    ``s3://bucket/warehouse/devops/`` but it would crawl straight through it,
    and a prefix test written only one way would miss precisely the broad
    crawler that does the most damage.
    """
    hits: List[str] = []
    targets = (crawler.get("Targets") or {}).get("S3Targets") or []
    for target in targets:
        path = (target.get("Path") or "").rstrip("/") + "/"
        for prefix in prefixes:
            if path.startswith(prefix) or prefix.startswith(path):
                hits.append(prefix)
    return sorted(set(hits))


def check_crawlers(
    glue_client_for: Callable[[str], Any],
    regions: Sequence[str] = CRAWLER_SCAN_REGIONS,
    databases: Optional[Dict[str, Dict[str, Any]]] = None,
) -> CheckResult:
    databases = databases if databases is not None else GOVERNED_DATABASES
    prefixes = _governed_prefixes(databases)
    result = CheckResult(
        check=CHECK_2,
        title="Glue crawlers across every scanned region, against the crawler prohibition",
    )
    inventory: List[Dict[str, Any]] = []
    regions_scanned: List[str] = []

    for region in regions:
        try:
            glue = glue_client_for(region)
            crawlers = _list_crawlers(glue)
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("crawler enumeration failed in %s", region)
            # A region that could not be scanned is NOT a region with no
            # crawlers. Recording the failure as a finding is what keeps the
            # check from reporting a clean estate it never actually looked at.
            result.findings.append(
                Finding(
                    check=CHECK_2,
                    subject="region:%s" % region,
                    severity=SEVERITY_BREACH,
                    kind="region_unscannable",
                    summary="Glue crawlers in %s could not be enumerated" % region,
                    observed={"error": str(exc)},
                    expected={"scannable": True},
                    steps_to_duplicate=[
                        "aws glue list-crawlers --profile product-lead --region %s" % region
                    ],
                    remediation=(
                        "The crawler sweep could not see this region. Until it can, the "
                        "estate's crawler count is unknown there -- which is the state "
                        "that let ten crawlers accumulate unnoticed in the first place."
                    ),
                )
            )
            continue

        regions_scanned.append(region)
        for crawler in crawlers:
            result.subjects_examined += 1
            name = crawler.get("Name", "")
            targets = [t.get("Path") for t in (crawler.get("Targets") or {}).get("S3Targets") or []]
            entry = {
                "name": name,
                "region": region,
                "database": crawler.get("DatabaseName"),
                "targets": targets,
                "schedule": (crawler.get("Schedule") or {}).get("ScheduleExpression"),
                "state": crawler.get("State"),
                "last_crawl": (crawler.get("LastCrawl") or {}).get("Status"),
            }
            inventory.append(entry)

            governed_hits = _targets_governed_prefix(crawler, prefixes)
            if governed_hits:
                result.findings.append(
                    Finding(
                        check=CHECK_2,
                        subject="%s@%s" % (name, region),
                        severity=SEVERITY_BREACH,
                        kind="crawler_on_governed_prefix",
                        summary="crawler %s in %s targets governed warehouse prefix %s"
                        % (name, region, ", ".join(governed_hits)),
                        observed=entry,
                        expected={"governed_prefixes_targeted": []},
                        steps_to_duplicate=[
                            "aws glue get-crawler --name %s --profile product-lead "
                            "--region %s" % (name, region),
                        ],
                        remediation=(
                            "A Glue crawler in a production data path is a governed "
                            "contract violation, full stop, with no exception for "
                            "governed T2 tables. The schema is a committed value written "
                            "by the export job through the B2-R2 shared library, not "
                            "something inferred by sampling S3. Remove the crawler; do "
                            "not narrow its target."
                        ),
                        references=["DOC-5E35E14DAD05", "DOC-F56858AFE749 obligation 3"],
                    )
                )
            else:
                result.findings.append(
                    Finding(
                        check=CHECK_2,
                        subject="%s@%s" % (name, region),
                        severity=SEVERITY_WARNING,
                        kind="crawler_present_off_governed_path",
                        summary="crawler %s exists in %s (database %s), outside any governed "
                        "warehouse prefix" % (name, region, crawler.get("DatabaseName")),
                        observed=entry,
                        expected={"note": "inventory only; not a violation on its own"},
                        steps_to_duplicate=[
                            "aws glue list-crawlers --profile product-lead --region %s" % region,
                        ],
                        remediation=(
                            "Reported so the estate cannot silently grow a crawler again. "
                            "This is not a violation and nothing here proposes deleting "
                            "it -- the target is outside every governed namespace. It "
                            "becomes a violation the moment its target moves."
                        ),
                        references=["DOC-5E35E14DAD05"],
                    )
                )

    result.detail = {
        "regions_scanned": regions_scanned,
        "governed_prefixes": prefixes,
        "crawlers": inventory,
    }
    return result


def _list_crawlers(glue_client) -> List[Dict[str, Any]]:
    names: List[str] = []
    token = None
    while True:
        kwargs: Dict[str, Any] = {}
        if token:
            kwargs["NextToken"] = token
        page = glue_client.list_crawlers(**kwargs)
        names.extend(page.get("CrawlerNames", []) or [])
        token = page.get("NextToken")
        if not token:
            break
    crawlers = []
    for name in names:
        crawlers.append(glue_client.get_crawler(Name=name).get("Crawler", {}))
    return crawlers


# ---------------------------------------------------------------------------
# Checks 3 and 4 -- one catalog walk, two questions
# ---------------------------------------------------------------------------


def _glue_tables(glue_client, database: str) -> List[Dict[str, Any]]:
    tables: List[Dict[str, Any]] = []
    token = None
    while True:
        kwargs: Dict[str, Any] = {"DatabaseName": database}
        if token:
            kwargs["NextToken"] = token
        page = glue_client.get_tables(**kwargs)
        tables.extend(page.get("TableList", []) or [])
        token = page.get("NextToken")
        if not token:
            break
    return tables


def check_namespace_isolation(
    s3_client, glue_client, databases: Optional[Dict[str, Dict[str, Any]]] = None
) -> CheckResult:
    databases = databases if databases is not None else GOVERNED_DATABASES
    result = CheckResult(
        check=CHECK_3,
        title="Tables in a governed namespace without a registered export job",
    )
    detail: List[Dict[str, Any]] = []

    for database, spec in sorted(databases.items()):
        project, bucket = spec["project"], spec["bucket"]
        quarantine = spec.get("tier") == "quarantine"
        try:
            tables = _glue_tables(glue_client, database)
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("get_tables failed for %s", database)
            result.error = "could not enumerate %s: %s" % (database, exc)
            continue

        registered = set()
        if not quarantine:
            try:
                registered = set(list_registered_tables(s3_client, bucket, project))
            except Exception as exc:  # noqa: BLE001
                LOGGER.exception("registration listing failed for %s", project)
                result.error = "could not list registrations for %s: %s" % (project, exc)
                continue

        baseline = LEGACY_UNREGISTERED_BASELINE.get(database, frozenset())

        for table in tables:
            name = table.get("Name", "")
            result.subjects_examined += 1
            entry = {
                "table": "hive.%s.%s" % (database, name),
                "registered": name in registered,
                "tier": spec.get("tier"),
            }
            detail.append(entry)

            if quarantine:
                # Quarantine tables are EXPECTED to be unregistered -- that is
                # what quarantine means. Counting them as violations would make
                # the ad-hoc on-ramp look like a permanent breach.
                continue
            if name in registered:
                continue

            legacy = name in baseline
            result.findings.append(
                Finding(
                    check=CHECK_3,
                    subject="hive.%s.%s" % (database, name),
                    severity=SEVERITY_WARNING if legacy else SEVERITY_BREACH,
                    kind="legacy_unregistered_table" if legacy else "unregistered_table",
                    summary=(
                        "hive.%s.%s has no B2-R2 registration record%s"
                        % (database, name, " (known legacy baseline)" if legacy else "")
                    ),
                    observed={
                        "expected_record": "s3://%s/warehouse-registrations/%s/%s.json"
                        % (bucket, project, name),
                        "location": (table.get("StorageDescriptor") or {}).get("Location"),
                        "on_legacy_baseline": legacy,
                        "baseline_taken_at": LEGACY_BASELINE_TAKEN_AT if legacy else None,
                    },
                    expected={"registration_record_present": True},
                    steps_to_duplicate=[
                        "aws glue get-table --database-name %s --name %s "
                        "--profile product-lead --region us-west-2" % (database, name),
                        "aws s3 ls s3://%s/warehouse-registrations/%s/%s.json "
                        "--profile product-lead --region us-west-2" % (bucket, project, name),
                    ],
                    remediation=(
                        "A table in a governed namespace should be traceable to a "
                        "registration record written by the code path that wrote its "
                        "data. This one arrived by some other route, and 'some other "
                        "route' is the risk. Either register it through the B2-R2 "
                        "shared library from its export job, or move it to hive.adhoc "
                        "where unregistered tables belong."
                        if not legacy
                        else
                        "Known gap, recorded against a dated baseline rather than "
                        "silenced. finance registers its Glue tables from its own "
                        "export code path but predates the sidecar registration "
                        "record, so freshness and full-refresh cannot be checked for "
                        "it. Closing the gap means having the finance export call "
                        "register_table()."
                    ),
                    references=["DOC-F56858AFE749 obligation 3", "DOC-04AF8A02A8F7"],
                )
            )

    result.detail["tables"] = detail
    return result


def check_storage_format(
    glue_client, databases: Optional[Dict[str, Dict[str, Any]]] = None
) -> CheckResult:
    databases = databases if databases is not None else GOVERNED_DATABASES
    result = CheckResult(
        check=CHECK_4,
        title="Storage format of every table in a governed namespace",
    )
    detail: List[Dict[str, Any]] = []

    for database, spec in sorted(databases.items()):
        try:
            tables = _glue_tables(glue_client, database)
        except Exception as exc:  # noqa: BLE001
            result.error = "could not enumerate %s: %s" % (database, exc)
            continue

        for table in tables:
            name = table.get("Name", "")
            result.subjects_examined += 1
            sd = table.get("StorageDescriptor") or {}
            serde = ((sd.get("SerdeInfo") or {}).get("SerializationLibrary") or "")
            input_format = sd.get("InputFormat") or ""
            classification = (table.get("Parameters") or {}).get("classification", "")
            entry = {
                "table": "hive.%s.%s" % (database, name),
                "serde": serde,
                "input_format": input_format,
                "classification": classification,
                "parquet": serde == REQUIRED_SERDE,
            }
            detail.append(entry)

            if serde == REQUIRED_SERDE:
                continue
            result.findings.append(
                Finding(
                    check=CHECK_4,
                    subject="hive.%s.%s" % (database, name),
                    severity=SEVERITY_BREACH,
                    kind="non_parquet_storage_format",
                    summary="hive.%s.%s is not stored as Parquet (serde %r)"
                    % (database, name, serde or "<none>"),
                    observed=entry,
                    expected={
                        "serde": REQUIRED_SERDE,
                        "input_format": REQUIRED_INPUT_FORMAT,
                        "classification": REQUIRED_CLASSIFICATION,
                    },
                    steps_to_duplicate=[
                        "aws glue get-table --database-name %s --name %s "
                        "--profile product-lead --region us-west-2 "
                        "--query 'Table.StorageDescriptor.SerdeInfo'" % (database, name),
                    ],
                    remediation=(
                        "Every governed table declares Parquet explicitly; the format is "
                        "never inherited from a Trino default. Re-export through the "
                        "B2-R2 shared library, which writes the storage descriptor as a "
                        "committed value. Note the check reads the SERDE, not the "
                        "`classification` parameter -- classification is a hint a "
                        "crawler writes, while the serde is what Trino uses to read the "
                        "bytes, and only one of those two can be wrong while queries "
                        "still succeed."
                    ),
                    references=["DOC-F56858AFE749 obligation 2", "DOC-04AF8A02A8F7"],
                )
            )

    result.detail["tables"] = detail
    return result
