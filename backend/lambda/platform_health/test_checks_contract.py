"""Tests for B6-R2 checks 2, 3 and 4 (DVP-TSK-695).

The load-bearing case here is multi-region. A single-region crawler sweep is not
a slightly-worse check, it is a check that would have reported a clean estate on
2026-08-08 while a live crawler ran in us-west-1 that same day. The test named
for that condition is the one to keep if any of these are ever pruned.
"""

from __future__ import annotations

from checks_contract import (
    _targets_governed_prefix,
    check_crawlers,
    check_namespace_isolation,
    check_storage_format,
)
from health_contract import REQUIRED_SERDE

DATABASES = {
    "devops": {"project": "devops", "bucket": "wh-bucket", "tier": "warehouse"},
    "adhoc": {"project": "adhoc", "bucket": "wh-bucket", "tier": "quarantine"},
}


def _crawler(name, path, database="somedb"):
    return {
        "Name": name,
        "DatabaseName": database,
        "Targets": {"S3Targets": [{"Path": path}]},
        "Schedule": {"ScheduleExpression": "cron(0 17 * * ? *)"},
        "State": "READY",
        "LastCrawl": {"Status": "SUCCEEDED"},
    }


class FakeGlueRegion:
    def __init__(self, crawlers=(), tables=()):
        self._crawlers = {c["Name"]: c for c in crawlers}
        self._tables = list(tables)

    def list_crawlers(self, **kwargs):
        return {"CrawlerNames": list(self._crawlers)}

    def get_crawler(self, Name):  # noqa: N803
        return {"Crawler": self._crawlers[Name]}

    def get_tables(self, **kwargs):
        return {"TableList": self._tables}


class FakeS3Registered:
    def __init__(self, registered):
        self.registered = registered

    def list_objects_v2(self, **kwargs):
        return {
            "Contents": [
                {"Key": "%s%s.json" % (kwargs["Prefix"], t)} for t in self.registered
            ],
            "IsTruncated": False,
        }


def _table(name, serde=REQUIRED_SERDE, location="s3://wh-bucket/warehouse/devops/x/"):
    return {
        "Name": name,
        "StorageDescriptor": {"Location": location, "SerdeInfo": {"SerializationLibrary": serde}},
        "Parameters": {"classification": "parquet"},
    }


# ---------------------------------------------------------------------------
# Check 2 -- the multi-region case
# ---------------------------------------------------------------------------


def test_a_single_region_sweep_would_miss_the_only_live_crawler():
    """The 2026-08-08 condition, reproduced. us-west-2 is empty because its ten
    crawlers were deleted; the surviving one is in us-west-1. Scanning only the
    home region reports a clean estate and is wrong."""
    regions = {
        "us-west-2": FakeGlueRegion(crawlers=[]),
        "us-west-1": FakeGlueRegion(
            crawlers=[_crawler("daily-data-crawler", "s3://jds-scraper-output/structured/")]
        ),
    }
    factory = lambda r: regions[r]  # noqa: E731

    home_only = check_crawlers(factory, regions=("us-west-2",), databases=DATABASES)
    assert home_only.subjects_examined == 0
    assert home_only.findings == []

    both = check_crawlers(factory, regions=("us-west-2", "us-west-1"), databases=DATABASES)
    assert both.subjects_examined == 1
    assert [f.subject for f in both.findings] == ["daily-data-crawler@us-west-1"]
    assert both.detail["regions_scanned"] == ["us-west-2", "us-west-1"]


def test_crawler_on_a_governed_prefix_is_a_breach():
    regions = {"us-west-2": FakeGlueRegion(
        crawlers=[_crawler("bad", "s3://wh-bucket/warehouse/devops/dim_record/")]
    )}
    result = check_crawlers(lambda r: regions[r], regions=("us-west-2",), databases=DATABASES)
    assert [f.kind for f in result.findings] == ["crawler_on_governed_prefix"]
    assert result.findings[0].severity == "breach"
    assert "DOC-5E35E14DAD05" in result.findings[0].references


def test_crawler_off_every_governed_prefix_is_a_warning_not_a_breach():
    """jds_scraper_db is not a governed namespace. Reporting it as a P0 would
    make the check cry wolf about a legitimate part of the estate."""
    regions = {"us-west-2": FakeGlueRegion(
        crawlers=[_crawler("elsewhere", "s3://other-bucket/data/")]
    )}
    result = check_crawlers(lambda r: regions[r], regions=("us-west-2",), databases=DATABASES)
    assert result.findings[0].severity == "warning"
    assert result.findings[0].kind == "crawler_present_off_governed_path"


def test_a_broad_crawler_above_a_governed_prefix_still_matches():
    """A crawler on s3://bucket/warehouse/ does not start with
    s3://bucket/warehouse/devops/ but would crawl straight through it. A
    one-directional prefix test misses exactly the crawler that does most harm."""
    assert _targets_governed_prefix(
        _crawler("broad", "s3://wh-bucket/warehouse/"),
        ["s3://wh-bucket/warehouse/devops/"],
    ) == ["s3://wh-bucket/warehouse/devops/"]


def test_an_unscannable_region_is_a_breach_not_a_silent_pass():
    class Boom:
        def list_crawlers(self, **kwargs):
            raise RuntimeError("AccessDenied")

    regions = {"us-west-2": FakeGlueRegion(crawlers=[]), "us-west-1": Boom()}
    result = check_crawlers(
        lambda r: regions[r], regions=("us-west-2", "us-west-1"), databases=DATABASES
    )
    assert [f.kind for f in result.findings] == ["region_unscannable"]
    assert result.detail["regions_scanned"] == ["us-west-2"]


# ---------------------------------------------------------------------------
# Check 3
# ---------------------------------------------------------------------------


def test_registered_table_produces_no_finding():
    glue = FakeGlueRegion(tables=[_table("dim_record")])
    result = check_namespace_isolation(
        FakeS3Registered(["dim_record"]), glue,
        databases={"devops": DATABASES["devops"]},
    )
    assert result.findings == []


def test_unregistered_table_in_a_governed_namespace_is_a_breach():
    glue = FakeGlueRegion(tables=[_table("mystery_upload")])
    result = check_namespace_isolation(
        FakeS3Registered([]), glue, databases={"devops": DATABASES["devops"]}
    )
    assert [f.kind for f in result.findings] == ["unregistered_table"]
    assert result.findings[0].severity == "breach"


def test_quarantine_tables_are_expected_to_be_unregistered():
    """hive.adhoc is the on-ramp. Counting its tables as violations would make
    the ad-hoc path look like a permanent breach of the contract it complies
    with."""
    glue = FakeGlueRegion(tables=[_table("some_csv")])
    result = check_namespace_isolation(
        FakeS3Registered([]), glue, databases={"adhoc": DATABASES["adhoc"]}
    )
    assert result.findings == []
    assert result.subjects_examined == 1


def test_legacy_baseline_downgrades_but_does_not_silence():
    glue = FakeGlueRegion(tables=[_table("accounts")])
    result = check_namespace_isolation(
        FakeS3Registered([]),
        glue,
        databases={"finance": {"project": "finance", "bucket": "f-bucket", "tier": "warehouse"}},
    )
    assert len(result.findings) == 1
    assert result.findings[0].severity == "warning"
    assert result.findings[0].kind == "legacy_unregistered_table"
    assert result.findings[0].observed["on_legacy_baseline"] is True


# ---------------------------------------------------------------------------
# Check 4
# ---------------------------------------------------------------------------


def test_parquet_table_passes():
    result = check_storage_format(
        FakeGlueRegion(tables=[_table("dim_record")]),
        databases={"devops": DATABASES["devops"]},
    )
    assert result.findings == []


def test_non_parquet_table_is_a_breach():
    result = check_storage_format(
        FakeGlueRegion(tables=[_table("csv_thing", serde="org.apache.hadoop.hive.serde2.OpenCSVSerde")]),
        databases={"devops": DATABASES["devops"]},
    )
    assert [f.kind for f in result.findings] == ["non_parquet_storage_format"]


def test_check_4_reads_the_serde_not_the_classification_hint():
    """classification is a hint a crawler writes; the serde is what Trino uses to
    read the bytes. A table can carry classification=parquet and a CSV serde, and
    only the serde determines whether queries return sense."""
    lying = _table("liar", serde="org.apache.hadoop.hive.serde2.OpenCSVSerde")
    lying["Parameters"]["classification"] = "parquet"
    result = check_storage_format(
        FakeGlueRegion(tables=[lying]), databases={"devops": DATABASES["devops"]}
    )
    assert len(result.findings) == 1
    assert result.findings[0].observed["classification"] == "parquet"
    assert result.findings[0].observed["parquet"] is False
