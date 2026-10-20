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

NOW = datetime(2026, 10, 19, 13, 15, 0, tzinfo=timezone.utc)  # prior day = 2026-10-18
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

    orig = mod.boto3
    mod.boto3 = FakeBoto
    try:
        out = mod.lambda_handler({"dry_run": True}, None)
    finally:
        mod.boto3 = orig
    assert calls["s3"] == 0 and out["keys"] == [] and out["ce_calls"] == 2
