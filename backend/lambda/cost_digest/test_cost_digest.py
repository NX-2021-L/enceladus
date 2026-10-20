"""Unit tests for cost_digest (ENC-TSK-R24). Stubbed CE / CloudWatch / S3 clients -- no AWS."""
import importlib.util
import json
import pathlib
import sys
from datetime import datetime, timezone

MODULE_PATH = pathlib.Path(__file__).with_name("lambda_function.py")
SPEC = importlib.util.spec_from_file_location("cost_digest", MODULE_PATH)
mod = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = mod
SPEC.loader.exec_module(mod)

NOW = datetime(2026, 10, 19, 13, 15, 0, tzinfo=timezone.utc)  # prior day = 2026-10-18 (a Monday)
TUESDAY = datetime(2026, 10, 20, 13, 15, 0, tzinfo=timezone.utc)
PRIOR = "2026-10-18"
CONTRACT_FIELDS = {
    "date", "prior_day_spend", "median_7d", "regression", "top_deltas",
    "feed_publisher_invocations", "invalidation_paths_mtd", "jreese_net_bytes",
    "devops_agentcli_compute_bytes", "tracker_rru_wcu", "generated_at", "ce_calls",
}


def _day(offset_from_prior: int) -> str:
    from datetime import date, timedelta
    return (date(2026, 10, 18) - timedelta(days=offset_from_prior)).isoformat()


class StubCE:
    """Distinguishes the ungrouped daily call from the USAGE_TYPE-grouped call."""

    def __init__(self, prior_spend=10.0, baseline=10.0, pages=1):
        self.prior_spend, self.baseline, self.pages = prior_spend, baseline, pages
        self.requests = []

    def get_cost_and_usage(self, **kw):
        self.requests.append(kw)
        if "GroupBy" not in kw:
            rows = []
            for off in range(7, -1, -1):  # 2026-10-11 .. 2026-10-18
                amt = self.prior_spend if off == 0 else self.baseline
                rows.append({"TimePeriod": {"Start": _day(off), "End": _day(off - 1)},
                             "Total": {"UnblendedCost": {"Amount": str(amt), "Unit": "USD"}}})
            return {"ResultsByTime": rows}
        # grouped: page counter via NextPageToken
        page = int(kw.get("NextPageToken", "0"))
        rows = []
        for off in range(17, -1, -1):  # 2026-10-01 .. 2026-10-18 (month start earlier than today-8)
            groups = [
                {"Keys": ["USW2-Requests-Tier1"], "Metrics": {
                    "UnblendedCost": {"Amount": "5" if off == 0 else "1"}, "UsageQuantity": {"Amount": "9"}}},
                {"Keys": ["Invalidations"], "Metrics": {
                    "UnblendedCost": {"Amount": "0"}, "UsageQuantity": {"Amount": "10" if off % 2 == 0 else "0"}}},
                {"Keys": ["USW2-Steady"], "Metrics": {
                    "UnblendedCost": {"Amount": "2"}, "UsageQuantity": {"Amount": "1"}}},
            ]
            rows.append({"TimePeriod": {"Start": _day(off), "End": _day(off - 1)}, "Groups": groups})
        resp = {"ResultsByTime": rows}
        if page + 1 < self.pages:
            resp["NextPageToken"] = str(page + 1)
        return resp


class StubCW:
    def __init__(self, region, data=None, fail=False):
        self.region, self.data, self.fail, self.calls = region, data or {}, fail, []

    def get_metric_data(self, **kw):
        self.calls.append(kw)
        if self.fail:
            raise RuntimeError("cw down")
        results = []
        for q in kw["MetricDataQueries"]:
            m = q["MetricStat"]["Metric"]
            key = (m["MetricName"], tuple(d["Value"] for d in m["Dimensions"]))
            results.append({"Id": q["Id"], "Values": self.data.get(key, [])})
        return {"MetricDataResults": results}


class StubS3:
    def __init__(self):
        self.puts = []

    def put_object(self, **kw):
        self.puts.append(kw)


def _cw_factory(fail=False):
    clients = {}
    data = {
        ("Invocations", ("devops-feed-publisher",)): [321.0],
        ("ConsumedReadCapacityUnits", ("devops-project-tracker",)): [1000.0, 500.0],
        ("ConsumedWriteCapacityUnits", ("devops-project-tracker",)): [250.0],
        ("BucketSizeBytes", ("jreese-net", "StandardStorage")): [2048.0, 1024.0],
        ("BucketSizeBytes", ("devops-agentcli-compute", "StandardStorage")): [4096.0],
    }

    def factory(region):
        if region not in clients:
            clients[region] = StubCW(region, data, fail)
        return clients[region]

    factory.clients = clients
    return factory


def test_payload_shape_and_values():
    ce = mod._CostExplorerBudget(StubCE(prior_spend=10.0, baseline=10.0))
    d = mod.build_digest(ce, _cw_factory(), NOW)
    assert CONTRACT_FIELDS.issubset(d)
    assert d["date"] == "2026-10-19" and d["prior_day_date"] == PRIOR
    assert d["prior_day_spend"] == 10.0 and d["median_7d"] == 10.0
    assert d["regression"] is False
    assert d["feed_publisher_invocations"] == 321
    assert d["tracker_rru_wcu"] == {"rru": 1500.0, "wcu": 250.0}
    assert d["jreese_net_bytes"] == {"current": 2048, "noncurrent": None}  # newest datapoint; no noncurrent dim
    assert d["devops_agentcli_compute_bytes"] == {"current": 4096, "noncurrent": None}
    assert d["invalidation_free_tier"] == 1000
    # noncurrent stays null WITH an explicit warning per bucket (no CloudWatch noncurrent type)
    assert sorted(d["warnings"]) == [
        "devops_agentcli_compute_bytes.noncurrent: null -- CloudWatch AWS/S3 has no noncurrent storage type",
        "jreese_net_bytes.noncurrent: null -- CloudWatch AWS/S3 has no noncurrent storage type",
    ]
    # invalidations: even offsets 0..16 contribute 10 each -> 9 days (0,2,...,16) = 90 (month start 2026-10-01 = off 17)
    assert d["invalidation_paths_mtd"] == 90
    assert d["ce_calls"] == 2 and d["generated_at"].endswith("Z")
    json.dumps(d)  # serializable


def test_top_deltas_ranked_by_abs_delta():
    ce = mod._CostExplorerBudget(StubCE())
    d = mod.build_digest(ce, _cw_factory(), NOW)
    top = d["top_deltas"]
    assert len(top) <= 5
    assert top[0]["usage_type"] == "USW2-Requests-Tier1"
    assert top[0]["prior_day"] == 5.0 and top[0]["mean_7d"] == 1.0 and top[0]["delta"] == 4.0
    assert "USW2-Steady" not in [t["usage_type"] for t in top]  # zero delta dropped


def test_regression_threshold_boundary():
    at = mod.compute_spend({_day(0): 12.0, **{_day(i): 10.0 for i in range(1, 8)}}, __import__("datetime").date(2026, 10, 18))
    over = mod.compute_spend({_day(0): 12.01, **{_day(i): 10.0 for i in range(1, 8)}}, __import__("datetime").date(2026, 10, 18))
    assert at[2] is False  # exactly 1.2x is NOT a regression (strictly greater)
    assert over[2] is True
    for r in (at, over):
        assert r[1] == 10.0


def test_regression_true_end_to_end_and_median_robust_to_outlier():
    ce = mod._CostExplorerBudget(StubCE(prior_spend=30.0, baseline=10.0))
    d = mod.build_digest(ce, _cw_factory(), NOW)
    assert d["regression"] is True and d["prior_day_spend"] == 30.0 and d["median_7d"] == 10.0


def test_ce_call_budget_never_exceeds_three_even_with_pagination():
    for pages in (1, 2, 5, 50):
        stub = StubCE(pages=pages)
        ce = mod._CostExplorerBudget(stub)
        d = mod.build_digest(ce, _cw_factory(), NOW)
        assert len(stub.requests) <= 3, pages
        assert d["ce_calls"] == len(stub.requests) <= 3
    assert d["ce_calls"] == 3 and any("ce_truncated" in w for w in d["warnings"])


def test_ce_budget_hard_stop():
    ce = mod._CostExplorerBudget(StubCE(), max_calls=1)
    ce.get_cost_and_usage(TimePeriod={}, Granularity="DAILY", Metrics=["UnblendedCost"])
    try:
        ce.get_cost_and_usage(TimePeriod={}, Granularity="DAILY", Metrics=["UnblendedCost"])
    except mod.CostExplorerBudgetExhausted:
        return
    raise AssertionError("expected CostExplorerBudgetExhausted")


def test_cloudwatch_failure_is_best_effort():
    ce = mod._CostExplorerBudget(StubCE())
    d = mod.build_digest(ce, _cw_factory(fail=True), NOW)
    assert d["prior_day_spend"] == 10.0 and d["feed_publisher_invocations"] is None
    assert d["jreese_net_bytes"] == {"current": None, "noncurrent": None}
    assert len(d["warnings"]) == 3 and d["ce_calls"] == 2


def test_bucket_metrics_use_bucket_regions():
    factory = _cw_factory()
    mod.build_digest(mod._CostExplorerBudget(StubCE()), factory, NOW)
    assert set(factory.clients) == {mod.WORKLOAD_REGION, mod.JREESE_NET_BUCKET_REGION, mod.COMPUTE_BUCKET_REGION}
    assert mod.JREESE_NET_BUCKET_REGION == "us-west-1"


def test_first_of_month_reports_previous_month_mtd():
    ce = StubCE()
    d = mod.build_digest(mod._CostExplorerBudget(ce), _cw_factory(), datetime(2026, 11, 1, 13, 15, tzinfo=timezone.utc))
    assert d["prior_day_date"] == "2026-10-31"
    grouped = [r for r in ce.requests if "GroupBy" in r][0]
    assert grouped["TimePeriod"]["End"] == "2026-11-01" and grouped["TimePeriod"]["Start"] <= "2026-10-01"


def test_s3_keys_and_compact_body():
    s3 = StubS3()
    d = mod.build_digest(mod._CostExplorerBudget(StubCE()), _cw_factory(), NOW)
    keys = mod.publish_digest(s3, d)
    assert keys == ["governance/cost-digest/2026-10-19.json", "governance/cost-digest/latest.json"]
    assert [p["Key"] for p in s3.puts] == keys
    assert all(p["Bucket"] == "jreese-net" and p["ContentType"] == "application/json" for p in s3.puts)
    body = s3.puts[0]["Body"].decode()
    assert body == json.dumps(json.loads(body), separators=(",", ":"))  # compact separators, no whitespace
    assert s3.puts[0]["Body"] == s3.puts[1]["Body"]
    assert json.loads(body)["date"] == "2026-10-19"


def test_handler_dry_run_makes_no_s3_writes(monkeypatch=None):
    calls = {"s3": 0}
    stub_ce = StubCE()

    class FakeBoto:
        @staticmethod
        def client(name, region_name=None):
            if name == "ce":
                assert region_name == "us-east-1"
                return stub_ce
            if name == "s3":
                calls["s3"] += 1
                return StubS3()
            return StubCW(region_name)

    orig, orig_now = mod.boto3, mod._utcnow
    mod.boto3 = FakeBoto
    mod._utcnow = lambda: TUESDAY  # weekday-independent: Mondays would add the compliance scan's S3 client
    try:
        out = mod.lambda_handler({"dry_run": True}, None)
    finally:
        mod.boto3, mod._utcnow = orig, orig_now
    assert calls["s3"] == 0 and out["keys"] == [] and out["ce_calls"] == 2
    assert out["compliance_scanned"] is False


# ---------------------------------------------------------------------------
# ENC-TSK-R38 weekly compliance scan (report-only) -- stubbed S3 / Logs / ECR / CloudWatch
# ---------------------------------------------------------------------------
from botocore.exceptions import ClientError  # noqa: E402


def _client_error(code, op="Op"):
    return ClientError({"Error": {"Code": code, "Message": "x"}}, op)


class StubComplianceS3:
    """Buckets: name -> (versioning Status|None, lifecycle rules list | None for 'no config' | Exception)."""

    def __init__(self, buckets, region="us-west-2"):
        self.buckets, self.region, self.calls = buckets, region, []

    def list_buckets(self):
        self.calls.append("list_buckets")
        return {"Buckets": [{"Name": n, "BucketRegion": self.region} for n in self.buckets]}

    def get_bucket_versioning(self, Bucket):
        self.calls.append(("versioning", Bucket))
        status, _ = self.buckets[Bucket]
        if isinstance(status, Exception):
            raise status
        return {"Status": status} if status else {}

    def get_bucket_lifecycle_configuration(self, Bucket):
        self.calls.append(("lifecycle", Bucket))
        _, rules = self.buckets[Bucket]
        if rules is None:
            raise _client_error("NoSuchLifecycleConfiguration")
        return {"Rules": rules}


NCV = {"Status": "Enabled", "NoncurrentVersionExpiration": {"NoncurrentDays": 30}}

S3_BUCKETS = {
    "enceladus-good": ("Enabled", [NCV]),
    "enceladus-no-config": ("Enabled", None),
    "devops-rule-without-ncv": ("Suspended", [{"Status": "Enabled", "Expiration": {"Days": 7}}]),
    "devops-ncv-disabled": ("Enabled", [{"Status": "Disabled", "NoncurrentVersionExpiration": {"NoncurrentDays": 7}}]),
    "jreese-net": ("Enabled", [NCV]),
    "support-lambda-artifacts-x": ("Enabled", None),
    "enceladus-unversioned": (None, None),
    "enceladus-denied": (_client_error("AccessDenied"), None),
    "someone-elses-bucket": ("Enabled", None),  # outside the prefix allow-list -> never touched
}


class StubLogs:
    def __init__(self, groups_by_prefix, page=2, fail=False):
        self.groups, self.page, self.fail, self.calls = groups_by_prefix, page, fail, []

    def describe_log_groups(self, **kw):
        self.calls.append(kw)
        if self.fail:
            raise _client_error("AccessDeniedException", "DescribeLogGroups")
        allg = self.groups.get(kw["logGroupNamePrefix"], [])
        start = int(kw.get("nextToken", 0))
        chunk = allg[start:start + self.page]
        resp = {"logGroups": chunk}
        if start + self.page < len(allg):
            resp["nextToken"] = str(start + self.page)
        return resp


class StubECR:
    def __init__(self, repos):
        self.repos, self.calls = repos, []  # name -> has_policy | Exception

    def describe_repositories(self, **kw):
        self.calls.append(("describe", kw))
        names = list(self.repos)
        start = int(kw.get("nextToken", 0))
        size = 2
        resp = {"repositories": [{"repositoryName": n} for n in names[start:start + size]]}
        if start + size < len(names):
            resp["nextToken"] = str(start + size)
        return resp

    def get_lifecycle_policy(self, repositoryName):
        self.calls.append(("policy", repositoryName))
        v = self.repos[repositoryName]
        if isinstance(v, Exception):
            raise v
        if not v:
            raise _client_error("LifecyclePolicyNotFoundException")
        return {"lifecyclePolicyText": "{}"}


class StubListMetrics:
    def __init__(self, per_namespace, page=3):
        self.per_ns, self.page, self.calls = per_namespace, page, []

    def list_metrics(self, Namespace, NextToken=None):
        self.calls.append((Namespace, NextToken))
        v = self.per_ns.get(Namespace, [])
        if isinstance(v, Exception):
            raise v
        start = int(NextToken or 0)
        resp = {"Metrics": v[start:start + self.page]}
        if start + self.page < len(v):
            resp["NextToken"] = str(start + self.page)
        return resp


def _metrics(n, name="M"):
    return [{"MetricName": name, "Dimensions": [{"Name": "Id", "Value": str(i)}]} for i in range(n)]


def _factory(s3=None, logs=None, ecr=None, cw=None):
    stubs = {"s3": s3 or StubComplianceS3({}), "logs": logs or StubLogs({}), "ecr": ecr or StubECR({}),
             "cloudwatch": cw or StubListMetrics({})}
    seen = []

    def client_for(service, region):
        seen.append((service, region))
        return stubs[service]

    client_for.seen, client_for.stubs = seen, stubs
    return client_for


def test_compliance_due_weekday_and_event_gating():
    assert mod.compliance_due(NOW, {}) == "weekly"  # Monday
    assert mod.compliance_due(TUESDAY, {}) is None
    assert mod.compliance_due(TUESDAY, None) is None
    assert mod.compliance_due(TUESDAY, {"compliance_scan": True}) == "event"
    assert mod.compliance_due(TUESDAY, {"compliance_scan": False}) is None
    assert mod.compliance_due(TUESDAY, {"compliance_scan": "true"}) is None  # strict boolean only
    assert mod.compliance_due(NOW, {"compliance_scan": True}) == "event"
    for d in range(14, 21):  # 2026-10-14..20 contains exactly one Monday (10-19)
        day = datetime(2026, 10, d, 13, 15, tzinfo=timezone.utc)
        assert (mod.compliance_due(day, {}) == "weekly") == (day.weekday() == 0)


def test_build_digest_without_scan_has_no_compliance_key():
    cf = _factory()
    # Tuesday + no flag: no compliance key, no compliance clients touched
    d = mod.build_digest(mod._CostExplorerBudget(StubCE()), _cw_factory(), TUESDAY, client_for=cf, event={})
    assert "compliance" not in d and cf.seen == []
    # No client factory (legacy call shape) on a Monday: unchanged behaviour
    d = mod.build_digest(mod._CostExplorerBudget(StubCE()), _cw_factory(), NOW)
    assert "compliance" not in d


def test_monday_and_event_runs_add_compliance_and_publish_to_both_keys():
    cf = _factory(s3=StubComplianceS3(S3_BUCKETS))
    for now, event, trig in ((NOW, {}, "weekly"), (TUESDAY, {"compliance_scan": True}, "event")):
        d = mod.build_digest(mod._CostExplorerBudget(StubCE()), _cw_factory(), now, client_for=cf, event=event)
        assert d["compliance"]["mode"] == "report_only" and d["compliance"]["trigger"] == trig
        assert {"s3_noncurrent_expiration", "log_group_retention", "ecr_lifecycle", "metric_dimensions"} <= set(d["compliance"])
        assert CONTRACT_FIELDS.issubset(d)  # top-level consumer contract untouched
        s3 = StubS3()
        mod.publish_digest(s3, d)
        assert [json.loads(p["Body"])["compliance"]["trigger"] for p in s3.puts] == [trig, trig]  # dated + latest


def test_s3_noncurrent_expiration_section():
    cf = _factory(s3=StubComplianceS3(S3_BUCKETS))
    out = mod.scan_s3_noncurrent_expiration(cf, mod._Deadline(60))
    flagged = {e["bucket"]: e for e in out["entries"]}
    assert set(flagged) == {"enceladus-no-config", "devops-rule-without-ncv", "devops-ncv-disabled", "support-lambda-artifacts-x"}
    assert flagged["enceladus-no-config"] == {"bucket": "enceladus-no-config", "versioning": "Enabled", "lifecycle_rules": 0}
    assert flagged["devops-rule-without-ncv"]["versioning"] == "Suspended"
    assert out["noncompliant"] == 4 and out["versioned"] == 6 and out["unversioned"] == 1
    assert out["item_errors"] == 1 and out["item_error_samples"] == ["enceladus-denied: ClientError:AccessDenied"]
    assert out["partial"] is False and out["entries_truncated"] is False
    # prefix allow-list: foreign bucket never inspected; unversioned bucket never gets a lifecycle read
    calls = cf.stubs["s3"].calls
    assert not any(isinstance(c, tuple) and c[1] == "someone-elses-bucket" for c in calls)
    assert ("lifecycle", "enceladus-unversioned") not in calls
    # report-only: only List/Get operations were ever invoked
    assert {c if isinstance(c, str) else c[0] for c in calls} <= {"list_buckets", "versioning", "lifecycle"}


def test_s3_list_cap_50_with_full_count():
    buckets = {f"enceladus-b{i:03d}": ("Enabled", None) for i in range(60)}
    out = mod.scan_s3_noncurrent_expiration(_factory(s3=StubComplianceS3(buckets)), mod._Deadline(60))
    assert out["noncompliant"] == 60 and len(out["entries"]) == 50 and out["entries_truncated"] is True


def test_log_group_retention_section_paginates_and_flags_missing_retention():
    logs = StubLogs({
        "/aws/lambda/enceladus-": [{"logGroupName": f"/aws/lambda/enceladus-a{i}", "retentionInDays": 30} for i in range(3)]
        + [{"logGroupName": "/aws/lambda/enceladus-forever"}],
        "/aws/lambda/devops-": [{"logGroupName": "/aws/lambda/devops-forever"}],
        "/aws/codebuild/enceladus": [{"logGroupName": "/aws/codebuild/enceladus-ok", "retentionInDays": 14}],
    })
    out = mod.scan_log_group_retention(_factory(logs=logs), mod._Deadline(60))
    assert out["checked"] == 6 and out["noncompliant"] == 2
    assert out["entries"] == ["/aws/lambda/enceladus-forever", "/aws/lambda/devops-forever"]
    assert out["scan_capped"] is False and out["partial"] is False
    assert any("nextToken" in c for c in logs.calls)  # paginated (page size 2, 4 groups under prefix 1)


def test_log_group_scan_cap_1000(monkeypatch=None):
    groups = {"/aws/lambda/enceladus-": [{"logGroupName": f"/aws/lambda/enceladus-{i}"} for i in range(1200)]}
    out = mod.scan_log_group_retention(_factory(logs=StubLogs(groups, page=50)), mod._Deadline(60))
    assert out["checked"] == 1000 and out["scan_capped"] is True
    assert out["noncompliant"] == 1000 and len(out["entries"]) == 50 and out["entries_truncated"] is True


def test_ecr_lifecycle_section():
    ecr = StubECR({"repo-a": True, "repo-b": False, "repo-c": False, "repo-d": _client_error("AccessDeniedException"), "repo-e": True})
    out = mod.scan_ecr_lifecycle(_factory(ecr=ecr), mod._Deadline(60))
    assert out["checked"] == 5 and out["entries"] == ["repo-b", "repo-c"] and out["noncompliant"] == 2
    assert out["item_errors"] == 1 and out["item_error_samples"] == ["repo-d: ClientError:AccessDeniedException"]
    assert {c[0] for c in ecr.calls} == {"describe", "policy"}  # no mutating calls


def test_metric_dimension_candidates():
    cw = StubListMetrics({
        "Enceladus/Prod": _metrics(120),          # 120 distinct dimension sets -> candidate
        "Enceladus/Docstore": _metrics(50),       # exactly the limit -> not a candidate
        "Enceladus/SnapStart": _metrics(80, "A") + _metrics(80, "B"),  # 160 metrics, 80 distinct sets
        "Enceladus/OpenSearch": RuntimeError("boom"),
    }, page=500)
    out = mod.scan_metric_dimensions(_factory(cw=cw), mod._Deadline(60))
    assert [(e["namespace"], e["distinct_dimension_sets"], e["metrics"]) for e in out["entries"]] == [
        ("Enceladus/Prod", 120, 120), ("Enceladus/SnapStart", 80, 160)]
    assert out["noncompliant"] == 2 and out["item_errors"] == 1
    assert out["item_error_samples"] == ["Enceladus/OpenSearch: RuntimeError"]
    assert out["dimension_set_limit"] == 50 and out["entries"][0]["truncated"] is False
    # empty namespaces are checked but never flagged
    assert out["checked"] == len(mod.COMPLIANCE_METRIC_NAMESPACES) - 1


def test_metric_page_cap_marks_lower_bound():
    cw = StubListMetrics({"Enceladus/Prod": _metrics(100)}, page=1)
    out = mod.scan_metric_dimensions(_factory(cw=cw), mod._Deadline(60))
    assert len([c for c in cw.calls if c[0] == "Enceladus/Prod"]) == mod.COMPLIANCE_METRIC_PAGE_CAP
    assert out["noncompliant"] == 0  # 10 pages x 1 metric = 10 sets: below limit, stays quiet
    cw = StubListMetrics({"Enceladus/Prod": _metrics(5500)}, page=500)  # 11 pages exist, 10 are read
    out = mod.scan_metric_dimensions(_factory(cw=cw), mod._Deadline(60))
    assert out["entries"][0]["truncated"] is True and out["entries"][0]["distinct_dimension_sets"] == 5000


def test_section_error_isolation_and_digest_still_published():
    cf = _factory(s3=StubComplianceS3(S3_BUCKETS), logs=StubLogs({}, fail=True))
    d = mod.build_digest(mod._CostExplorerBudget(StubCE()), _cw_factory(), NOW, client_for=cf, event={})
    comp = d["compliance"]
    assert comp["log_group_retention"]["error"].startswith("ClientError:AccessDeniedException")
    assert comp["s3_noncurrent_expiration"]["noncompliant"] == 4  # other sections unaffected
    assert comp["ecr_lifecycle"]["checked"] == 0 and comp["metric_dimensions"]["checked"] == len(mod.COMPLIANCE_METRIC_NAMESPACES)
    assert "compliance.log_group_retention: ClientError" in d["warnings"]
    assert CONTRACT_FIELDS.issubset(d) and d["prior_day_spend"] == 10.0
    json.dumps(d)


def test_client_factory_failure_is_isolated_per_section():
    def bad_client_for(service, region):
        if service == "ecr":
            raise RuntimeError("no ecr endpoint")
        return _factory().stubs[service]

    comp = mod.collect_compliance(bad_client_for, "weekly")
    assert comp["ecr_lifecycle"] == {"error": "RuntimeError: no ecr endpoint"}
    assert "error" not in comp["log_group_retention"]


def test_wall_clock_budget_marks_partial():
    ticks = iter(range(0, 10_000))
    # every clock() call advances 10s: the 4-way split of a 20s budget (5s each) expires immediately
    comp = mod.collect_compliance(_factory(s3=StubComplianceS3(S3_BUCKETS)), "weekly", budget_seconds=20,
                                  clock=lambda: next(ticks) * 10.0)
    for key in ("s3_noncurrent_expiration", "log_group_retention", "ecr_lifecycle", "metric_dimensions"):
        assert comp[key]["partial"] is True and comp[key]["checked"] == 0


def test_handler_monday_runs_scan_in_dry_run_without_writes_and_uses_regional_clients():
    made = []
    s3_stub = StubComplianceS3(S3_BUCKETS)

    class FakeBoto:
        @staticmethod
        def client(name, region_name=None):
            made.append((name, region_name))
            if name == "ce":
                return StubCE()
            if name == "s3":
                return s3_stub
            if name == "logs":
                return StubLogs({"/aws/lambda/devops-": [{"logGroupName": "/aws/lambda/devops-x"}]})
            if name == "ecr":
                return StubECR({"r": False})
            return StubCW(region_name)

    orig, orig_now = mod.boto3, mod._utcnow
    mod.boto3, mod._utcnow = FakeBoto, lambda: NOW
    try:
        out = mod.lambda_handler({"dry_run": True}, None)
    finally:
        mod.boto3, mod._utcnow = orig, orig_now
    assert out["compliance_scanned"] is True and out["keys"] == []
    assert ("logs", mod.WORKLOAD_REGION) in made and ("ecr", mod.WORKLOAD_REGION) in made
    assert sum(1 for c in made if c[0] == "s3") == 2  # digest-region list client + the bucket's own region client
