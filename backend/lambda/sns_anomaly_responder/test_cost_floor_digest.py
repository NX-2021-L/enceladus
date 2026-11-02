"""ENC-TSK-R83-0C: weekly fixed-floor magnitude digest adapter (fixture inventories)."""
import json
import os
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[2] / "tools"))
os.environ.setdefault("COORDINATION_INTERNAL_API_KEY", "test")

import cost_floor_digest as cf  # noqa: E402
import lambda_function as lf  # noqa: E402
import source_adapters as sa  # noqa: E402
from test_sns_anomaly_responder import FakeTracker  # noqa: E402


def _inv(extra=()):
    items = [
        {"kind": "nat_gateway", "id": "nat-03b3449aaddf5ef04", "name": "gamma-nat", "attrs": {}},
        {"kind": "eip", "id": "44.245.109.234", "name": "", "attrs": {"associated": True}},
        {"kind": "opensearch_domain", "id": "OpenSearchNodeInstance", "name": "",
         "attrs": {"instance_type": "t3.small.search", "instance_count": 1, "ebs_gb": 10}},
        {"kind": "ec2_instance", "id": "i-stopped", "name": "", "attrs": {"instance_type": "t3.large", "state": "stopped"}},
        {"kind": "lightsail_static_ip", "id": "ls-attached", "name": "", "attrs": {"attached": True}},
    ] + [{"kind": "vpc_endpoint", "id": f"vpce-{n:02d}", "name": "svc", "attrs": {"subnet_count": 1}} for n in range(9)]
    return json.dumps({"schema": cf.SNAPSHOT_SCHEMA, "items": list(items) + list(extra), "errors": []})


def test_top_n_ordering_floor_and_non_billing_skipped(monkeypatch):
    monkeypatch.setenv("FLOOR_DIGEST_TOP_N", "4")
    out = cf.parse(_inv())
    assert [a["anomaly_id"] for a in out] == [
        "nat-gateway-nat-03b3449aaddf5ef04", "opensearch-domain-opensearchnodeinstance",
        "vpc-endpoint-vpce-00", "vpc-endpoint-vpce-01"]
    assert out[0]["impact"]["monthly_usd"] == pytest.approx(32.85)
    assert out[2]["impact"]["monthly_usd"] == pytest.approx(7.30)
    assert out[1]["impact"]["monthly_usd"] == pytest.approx(0.036 * 730 + 10 * 0.122)
    assert [a["breakdown"][0]["rank"] for a in out] == [1, 2, 3, 4]


def test_floor_and_excluded_items(monkeypatch):
    monkeypatch.setenv("FLOOR_DIGEST_TOP_N", "50")
    ids = {a["anomaly_id"] for a in cf.parse(_inv())}
    assert "ec2-instance-i-stopped" not in ids and "lightsail-static-ip-ls-attached" not in ids
    assert "eip-44.245.109.234" in ids  # $3.65 >= $3 floor
    monkeypatch.setenv("FLOOR_DIGEST_MIN_MONTHLY_USD", "10")
    assert {a["anomaly_id"] for a in cf.parse(_inv())} == {
        "nat-gateway-nat-03b3449aaddf5ef04", "opensearch-domain-opensearchnodeinstance"}


def test_unpriced_sorts_after_priced_and_is_not_dropped(monkeypatch):
    monkeypatch.setenv("FLOOR_DIGEST_TOP_N", "50")
    odd = {"kind": "rds_instance", "id": "db-x", "name": "", "attrs": {"instance_class": "db.x2g.16xlarge"}}
    out = cf.parse(_inv([odd]))
    assert out[-1]["anomaly_id"] == "rds-instance-db-x" and out[-1]["impact"]["monthly_usd"] is None


def test_stable_anomaly_id_and_impact_across_weeks_and_order(monkeypatch):
    week1, week2 = json.loads(_inv()), json.loads(_inv())
    week2["items"].reverse()
    a, b = cf.parse(json.dumps(week1)), cf.parse(json.dumps(week2))
    assert [x["anomaly_id"] for x in a] == [x["anomaly_id"] for x in b]
    assert [x["impact"] for x in a] == [x["impact"] for x in b]
    for x in a:
        sa.validate_normalized(dict(x), "cost-floor")
        assert x["project"] == "devops" and f"[cost-floor:{x['anomaly_id']}]" in x["title"]
        assert x["evidence"][0]["source_key"] == f"cost-floor:{x['anomaly_id']}"


def test_registered_and_garbage_yields_nothing():
    assert "cost-floor" in sa.REGISTRY.sources()
    assert cf.parse("not json") == [] and cf.parse(json.dumps({"schema": "other"})) == []


def test_second_run_updates_not_duplicates():
    tracker = FakeTracker()
    snap = _inv()
    first = lf.run_scheduled_digest({"digest_source": "cost-floor"}, tracker, collect=lambda: snap)
    n_created = len(tracker.created) if hasattr(tracker, "created") else None
    second = lf.run_scheduled_digest({"digest_source": "cost-floor"}, tracker, collect=lambda: snap)
    assert {r["action"] for r in first["results"]} == {"created"}
    assert {r["action"] for r in second["results"]} == {"replayed"}
    assert [r["issue_id"] for r in first["results"]] == [r["issue_id"] for r in second["results"]]
    if n_created is not None:
        assert len(tracker.created) == n_created


def test_handler_routes_scheduled_event(monkeypatch):
    monkeypatch.setattr(cf, "collect_message", lambda clients=None: _inv())
    out = lf.lambda_handler({"digest_source": "cost-floor"}, None, client=FakeTracker())
    assert out["summary"]["event"] == "anomaly_digest_complete" and out["summary"]["processed"] >= 3
    with pytest.raises(RuntimeError):
        lf.lambda_handler({"digest_source": "nope"}, None, client=FakeTracker())


class _Recorder:
    """Fake boto3 clients; records every service requested so the test can prove 'ce' is never built."""
    def __init__(self):
        self.services = []

    def __call__(self, service):
        self.services.append(service)
        return _FakeClient(service)


class _FakeClient:
    def __init__(self, service):
        self.service = service

    def can_paginate(self, op):
        return False

    def describe_nat_gateways(self):
        return {"NatGateways": [{"NatGatewayId": "nat-1", "State": "available"}, {"NatGatewayId": "nat-2", "State": "deleted"}]}

    def describe_addresses(self):
        return {"Addresses": [{"PublicIp": "1.2.3.4", "AssociationId": "eipassoc-1"}]}

    def describe_vpc_endpoints(self):
        return {"VpcEndpoints": [{"VpcEndpointId": "vpce-1", "VpcEndpointType": "Interface", "State": "available", "SubnetIds": ["s1", "s2"]},
                                 {"VpcEndpointId": "vpce-gw", "VpcEndpointType": "Gateway", "State": "available"}]}

    def describe_instances(self):
        return {"Reservations": [{"Instances": [{"InstanceId": "i-1", "InstanceType": "t3.micro", "State": {"Name": "running"}}]}]}

    def list_domain_names(self):
        return {"DomainNames": [{"DomainName": "d1"}]}

    def describe_domains(self, DomainNames):
        return {"DomainStatusList": [{"DomainName": "d1", "ClusterConfig": {"InstanceType": "t3.small.search", "InstanceCount": 1},
                                      "EBSOptions": {"EBSEnabled": True, "VolumeSize": 10}}]}

    def describe_db_instances(self):
        raise RuntimeError("AccessDenied")

    def get_instances(self):
        return {"instances": [{"name": "ls1", "bundleId": "nano_3_0"}]}

    def get_static_ips(self):
        return {"staticIps": [{"name": "sip", "isAttached": False}]}


def test_collect_is_read_only_inventory_and_never_builds_cost_explorer_client():
    rec = _Recorder()
    snap = json.loads(cf.collect_message(clients=rec))
    assert set(rec.services) == {"ec2", "opensearch", "rds", "lightsail"}
    assert "ce" not in rec.services
    assert len(snap["errors"]) == 1 and snap["errors"][0].startswith("rds:")  # one failure never aborts the rest
    kinds = sorted(i["kind"] for i in snap["items"])
    assert kinds == ["ec2_instance", "eip", "lightsail_instance", "lightsail_static_ip", "nat_gateway", "opensearch_domain", "vpc_endpoint"]
    ep = next(i for i in snap["items"] if i["kind"] == "vpc_endpoint")
    assert cf.price_item(ep)["monthly_usd"] == pytest.approx(14.60)  # 2 AZs
    src = (HERE / "cost_floor_digest.py").read_text()
    assert "costexplorer" not in src.lower() and '"ce"' not in src and "'ce'" not in src
    assert "get_cost_and_usage" not in src


def test_shares_c3_definition_with_cost_resource_guard():
    import cost_resource_guard as g
    covered = {t for types in cf.COVERED_CFN_TYPES.values() for t in types}
    assert covered <= set(g.NONPROD_C3_TYPES), "digest covers a type the C3 guard does not define"
    # guard C3 types the inventory does not (yet) collect -- explicit so a NEW guard type fails here
    known_gaps = {"AWS::RDS::DBCluster", "AWS::OpenSearchServerless::Collection", "AWS::ElastiCache::CacheCluster",
                  "AWS::ElastiCache::ReplicationGroup", "AWS::MemoryDB::Cluster", "AWS::Redshift::Cluster",
                  "AWS::Lightsail::Database"}
    assert set(g.NONPROD_C3_TYPES) - covered == known_gaps
