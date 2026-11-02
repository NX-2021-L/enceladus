"""Fixed-floor magnitude digest: second anomaly adapter (ENC-TSK-R83-0C, ENC-FTR-150 W3.3).

BRD DOC-8E2CFF602B33 section 3.1 item 3: a weekly instrument that ranks the persistent-class (C3,
always-on, monthly-billed) resources the account actually owns by LIST price and files one governed
issue per resource above a fixed dollar floor. It is the "magnitude" counterpart to the delta-based
Cost Anomaly Detection adapter: a flat, forgotten NAT gateway never spikes, so CAD never fires on it.

COST EXPLORER IS NEVER USED (DOC-323ED181F51D rule 7). Cost comes from the static, versioned
PRICE TABLE below applied to describe-*/list-* inventory; this module never constructs a ``ce``
client, so the digest adds no per-call Cost Explorer charge.

Shape (keeps the adapter contract of source_adapters.py intact):

* ``collect_message(clients=None)``  -- the only network step: read-only describe/list calls,
  returns a JSON inventory snapshot (raw attributes only, no prices).
* ``parse(message)``                  -- pure and deterministic: snapshot -> priced -> floor -> top N
  -> NormalizedAnomaly list. anomaly_id = ``{kind}-{resource id}`` only, so a resource that persists
  from week to week maps to the SAME dedupe key and refreshes one issue instead of minting a new one.

The lambda handler runs ``collect_message`` -> ``parse`` for a scheduled event
``{"digest_source": "cost-floor"}`` and pushes the result through the same idempotent
``process_anomaly`` create path used for SNS-delivered anomalies.

C3 coverage: ``COVERED_CFN_TYPES`` maps each inventory kind to the CloudFormation types of
``tools/cost_resource_guard.NONPROD_C3_TYPES`` (DVP-TSK-B89). The Lambda zip cannot import from
tools/, so ``test_cost_floor_digest`` asserts every covered type is in that list and that the
remaining guard types are explicitly accounted for -- one definition, drift fails CI.
"""
from __future__ import annotations

import json
import os
from typing import Any, Callable, Dict, Iterable, List, Optional

SOURCE = "cost-floor"
DEFAULT_PROJECT = "devops"
SNAPSHOT_SCHEMA = "cost-floor-inventory/1"
HOURS_PER_MONTH = 730.0

# --- static list prices: us-west-2, on-demand, USD per month (730 h) -------------------------------
PRICE_TABLE_VERSION = "2026-11-02"
PRICE_TABLE_REGION = "us-west-2"
PRICE_TABLE_TAKEN = "2026-11-02"  # date these list prices were taken (public AWS/Lightsail price pages)

PRICES: Dict[str, Any] = {
    "nat_gateway": 0.045 * HOURS_PER_MONTH,           # per gateway-hour; data processing excluded (floor)
    "eip": 0.005 * HOURS_PER_MONTH,                   # public IPv4 per address-hour (in-use or idle)
    "vpc_endpoint_interface_per_az": 0.01 * HOURS_PER_MONTH,  # per endpoint per AZ/subnet
    "ec2_hourly": {
        "t3.nano": 0.0052, "t3.micro": 0.0104, "t3.small": 0.0208, "t3.medium": 0.0416,
        "t3.large": 0.0832, "t3.xlarge": 0.1664, "t3.2xlarge": 0.3328,
        "t4g.nano": 0.0042, "t4g.micro": 0.0084, "t4g.small": 0.0168, "t4g.medium": 0.0336,
        "t4g.large": 0.0672, "t4g.xlarge": 0.1344, "t4g.2xlarge": 0.2688,
        "m5.large": 0.096, "m5.xlarge": 0.192, "m6g.large": 0.077, "m6g.xlarge": 0.154,
        "c5.large": 0.085, "c6g.large": 0.068, "r5.large": 0.126, "r6g.large": 0.1008,
    },
    "opensearch_hourly": {
        "t3.small.search": 0.036, "t3.medium.search": 0.073, "t3.large.search": 0.146,
        "m6g.large.search": 0.128, "m6g.xlarge.search": 0.256, "r6g.large.search": 0.167,
        "r6g.xlarge.search": 0.334, "m5.large.search": 0.142, "r5.large.search": 0.186,
    },
    "opensearch_ebs_gb_month": 0.122,                  # gp3
    "rds_hourly": {                                    # single-AZ; Multi-AZ doubles
        "db.t4g.micro": 0.016, "db.t4g.small": 0.032, "db.t4g.medium": 0.065, "db.t4g.large": 0.129,
        "db.t3.micro": 0.017, "db.t3.small": 0.034, "db.t3.medium": 0.068, "db.t3.large": 0.136,
        "db.m6g.large": 0.159, "db.m5.large": 0.178, "db.r6g.large": 0.26, "db.r5.large": 0.24,
    },
    "rds_storage_gb_month": 0.115,
    "lightsail_bundle_month": {
        "nano": 5.0, "micro": 7.0, "small": 12.0, "medium": 24.0, "large": 44.0,
        "xlarge": 84.0, "2xlarge": 164.0,
    },
    "lightsail_static_ip_unattached": 0.005 * HOURS_PER_MONTH,  # attached static IPs are free
}

# inventory kind -> CloudFormation types of tools/cost_resource_guard.NONPROD_C3_TYPES it covers
COVERED_CFN_TYPES: Dict[str, List[str]] = {
    "nat_gateway": ["AWS::EC2::NatGateway"],
    "eip": ["AWS::EC2::EIP"],
    "vpc_endpoint": ["AWS::EC2::VPCEndpoint"],
    "ec2_instance": ["AWS::EC2::Instance"],
    "opensearch_domain": ["AWS::OpenSearchService::Domain", "AWS::Elasticsearch::Domain"],
    "rds_instance": ["AWS::RDS::DBInstance"],
    "lightsail_instance": ["AWS::Lightsail::Instance"],
    "lightsail_static_ip": [],  # not a guard type (free when attached); inventoried for idle-IP cost
}


def _fnum(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        return default


def settings() -> Dict[str, Any]:
    try:
        top_n = int(os.environ.get("FLOOR_DIGEST_TOP_N", "") or 10)
    except ValueError:
        top_n = 10
    return {"top_n": max(1, top_n), "min_monthly_usd": _fnum("FLOOR_DIGEST_MIN_MONTHLY_USD", 3.0)}


# --- pricing (pure) ---------------------------------------------------------------------------------
def price_item(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Return {"monthly_usd": float|None, "basis": str} for one inventory item, or None to skip it
    (not billing: e.g. a stopped instance, a deleted NAT gateway)."""
    kind, a = item.get("kind"), item.get("attrs") or {}
    if kind == "nat_gateway":
        return {"monthly_usd": PRICES["nat_gateway"], "basis": "NAT gateway-hour x 730 (excl. data processing)"}
    if kind == "eip":
        return {"monthly_usd": PRICES["eip"], "basis": "public IPv4 address-hour x 730"}
    if kind == "vpc_endpoint":
        azs = max(1, int(a.get("subnet_count") or 1))
        return {"monthly_usd": PRICES["vpc_endpoint_interface_per_az"] * azs,
                "basis": f"interface endpoint x {azs} AZ x $0.01/h x 730"}
    if kind == "ec2_instance":
        if a.get("state") not in ("running", "pending"):
            return None
        rate = PRICES["ec2_hourly"].get(a.get("instance_type"))
        return {"monthly_usd": None if rate is None else rate * HOURS_PER_MONTH,
                "basis": f"EC2 {a.get('instance_type')} on-demand Linux x 730"}
    if kind == "opensearch_domain":
        rate = PRICES["opensearch_hourly"].get(a.get("instance_type"))
        if rate is None:
            return {"monthly_usd": None, "basis": f"OpenSearch {a.get('instance_type')} (unpriced)"}
        count = max(1, int(a.get("instance_count") or 1))
        ebs = float(a.get("ebs_gb") or 0) * PRICES["opensearch_ebs_gb_month"] * count
        return {"monthly_usd": rate * HOURS_PER_MONTH * count + ebs,
                "basis": f"OpenSearch {a.get('instance_type')} x {count} x 730 + {a.get('ebs_gb') or 0} GB gp3 x {count}"}
    if kind == "rds_instance":
        rate = PRICES["rds_hourly"].get(a.get("instance_class"))
        if rate is None:
            return {"monthly_usd": None, "basis": f"RDS {a.get('instance_class')} (unpriced)"}
        mult = 2 if a.get("multi_az") else 1
        return {"monthly_usd": (rate * HOURS_PER_MONTH + float(a.get("allocated_gb") or 0) * PRICES["rds_storage_gb_month"]) * mult,
                "basis": f"RDS {a.get('instance_class')} x730 + {a.get('allocated_gb') or 0} GB" + (" x2 Multi-AZ" if mult == 2 else "")}
    if kind == "lightsail_instance":
        size = str(a.get("bundle_id") or "").split("_")[0]
        price = PRICES["lightsail_bundle_month"].get(size)
        return {"monthly_usd": price, "basis": f"Lightsail bundle {a.get('bundle_id')} flat monthly"}
    if kind == "lightsail_static_ip":
        if a.get("attached"):
            return None
        return {"monthly_usd": PRICES["lightsail_static_ip_unattached"], "basis": "Lightsail static IP unattached x 730"}
    return None


def rank(items: Iterable[Dict[str, Any]], top_n: int, floor_usd: float) -> List[Dict[str, Any]]:
    """Priced items at/above the floor, descending by price (ties by stable id); unpriced items
    (unknown size) sort after priced ones so a new instance class is surfaced, not silently dropped."""
    rows: List[Dict[str, Any]] = []
    for it in items:
        priced = price_item(it)
        if priced is None or not it.get("id"):
            continue
        usd = priced["monthly_usd"]
        if usd is not None and usd < floor_usd:
            continue
        rows.append({"item": it, "usd": usd, "basis": priced["basis"],
                     "anomaly_id": f"{it['kind']}-{it['id']}".lower().replace("_", "-").replace(" ", "-")})
    rows.sort(key=lambda r: (r["usd"] is None, -(r["usd"] or 0.0), r["anomaly_id"]))
    return rows[:top_n]


def _severity(usd: Optional[float]) -> Dict[str, str]:
    if usd is None or usd >= 25.0:
        return {"severity": "medium", "priority": "P2"}
    return {"severity": "low", "priority": "P3"}


def parse(message: str) -> List[Dict[str, Any]]:
    try:
        snap = json.loads(message)
    except (TypeError, ValueError):
        return []
    if not isinstance(snap, dict) or snap.get("schema") != SNAPSHOT_SCHEMA:
        return []
    cfg = settings()
    project = os.environ.get("ANOMALY_DEFAULT_PROJECT", DEFAULT_PROJECT).strip() or DEFAULT_PROJECT
    ranked = rank([i for i in snap.get("items") or [] if isinstance(i, dict)], cfg["top_n"], cfg["min_monthly_usd"])
    out: List[Dict[str, Any]] = []
    for pos, row in enumerate(ranked, 1):
        it, aid, usd = row["item"], row["anomaly_id"], row["usd"]
        usd_r = None if usd is None else round(usd, 2)
        # impact is a pure function of the resource + price table: unchanged week-to-week, so a
        # persisting resource logs a refresh on its one issue instead of appending new evidence.
        impact = {"monthly_usd": usd_r, "kind": it["kind"], "price_table_version": PRICE_TABLE_VERSION}
        label = f"{it['kind']} {it['id']}" + (f" ({it.get('name')})" if it.get("name") else "")
        cost_txt = "unpriced" if usd_r is None else f"~${usd_r:,.2f}/mo"
        key = f"{SOURCE}:{aid}"
        out.append({
            "source": SOURCE,
            "anomaly_id": aid,
            "project": project,
            "title": f"[cost-floor] Persistent resource {label} {cost_txt} [{key}]",
            "evidence": [{
                "description": (f"Fixed-floor digest: {label} is a persistent (C3) resource at list price {cost_txt} "
                                f"({row['basis']}); price table {PRICE_TABLE_VERSION} {PRICE_TABLE_REGION} on-demand."),
                "observed_by": "sns-anomaly-responder",
                "steps_to_duplicate": [
                    f"Describe the {it['kind']} inventory in {PRICE_TABLE_REGION} (read-only describe/list) and find {it['id']}",
                    "Re-run the weekly cost-floor digest: aws lambda invoke the responder with {\"digest_source\":\"cost-floor\"}",
                ],
                "source": SOURCE,
                "anomaly_id": aid,
                "source_key": key,
                "impact": impact,
            }],
            "impact": impact,
            "breakdown": [{"driver": row["basis"], "monthly_usd": usd_r, "rank": pos}],
            "severity": _severity(usd)["severity"],
            "priority": _severity(usd)["priority"],
            "category": "risk",
            "raw_ref": None,
        })
    return out


# --- inventory (the only network step; read-only describe/list; never Cost Explorer) ------------------
def _client_factory(region: str) -> Callable[[str], Any]:
    import boto3  # lazy: parse() and the tests need no AWS SDK

    return lambda service: boto3.client(service, region_name=region)


def _name_tag(tags: Any) -> str:
    for t in tags or []:
        if t.get("Key") == "Name":
            return str(t.get("Value") or "")
    return ""


def _paged(client: Any, op: str, key: str, **kw: Any) -> Iterable[Dict[str, Any]]:
    if client.can_paginate(op):
        for page in client.get_paginator(op).paginate(**kw):
            yield from page.get(key) or []
    else:
        yield from getattr(client, op)(**kw).get(key) or []


def _collect_ec2(c: Callable[[str], Any]) -> List[Dict[str, Any]]:
    ec2, items = c("ec2"), []
    for n in _paged(ec2, "describe_nat_gateways", "NatGateways"):
        if n.get("State") in ("available", "pending"):
            items.append({"kind": "nat_gateway", "id": n["NatGatewayId"], "name": _name_tag(n.get("Tags")), "attrs": {}})
    for a in ec2.describe_addresses().get("Addresses") or []:
        items.append({"kind": "eip", "id": a.get("PublicIp") or a.get("AllocationId"), "name": _name_tag(a.get("Tags")),
                      "attrs": {"associated": bool(a.get("AssociationId"))}})
    for e in _paged(ec2, "describe_vpc_endpoints", "VpcEndpoints"):
        if e.get("VpcEndpointType") == "Interface" and e.get("State") in ("available", "pending", "pendingAcceptance"):
            items.append({"kind": "vpc_endpoint", "id": e["VpcEndpointId"], "name": e.get("ServiceName", ""),
                          "attrs": {"subnet_count": len(e.get("SubnetIds") or [])}})
    for r in _paged(ec2, "describe_instances", "Reservations"):
        for i in r.get("Instances") or []:
            items.append({"kind": "ec2_instance", "id": i["InstanceId"], "name": _name_tag(i.get("Tags")),
                          "attrs": {"instance_type": i.get("InstanceType"), "state": (i.get("State") or {}).get("Name")}})
    return items


def _collect_opensearch(c: Callable[[str], Any]) -> List[Dict[str, Any]]:
    os_c = c("opensearch")
    names = [d["DomainName"] for d in os_c.list_domain_names().get("DomainNames") or []]
    items = []
    for i in range(0, len(names), 5):
        for d in os_c.describe_domains(DomainNames=names[i:i + 5]).get("DomainStatusList") or []:
            cc, ebs = d.get("ClusterConfig") or {}, d.get("EBSOptions") or {}
            items.append({"kind": "opensearch_domain", "id": d["DomainName"], "name": "",
                          "attrs": {"instance_type": cc.get("InstanceType"), "instance_count": cc.get("InstanceCount"),
                                    "ebs_gb": ebs.get("VolumeSize") if ebs.get("EBSEnabled") else 0}})
    return items


def _collect_rds(c: Callable[[str], Any]) -> List[Dict[str, Any]]:
    return [{"kind": "rds_instance", "id": d["DBInstanceIdentifier"], "name": "",
             "attrs": {"instance_class": d.get("DBInstanceClass"), "multi_az": bool(d.get("MultiAZ")),
                       "allocated_gb": d.get("AllocatedStorage") or 0}}
            for d in _paged(c("rds"), "describe_db_instances", "DBInstances")]


def _collect_lightsail(c: Callable[[str], Any]) -> List[Dict[str, Any]]:
    ls, items = c("lightsail"), []
    for i in ls.get_instances().get("instances") or []:
        items.append({"kind": "lightsail_instance", "id": i["name"], "name": "", "attrs": {"bundle_id": i.get("bundleId")}})
    for s in ls.get_static_ips().get("staticIps") or []:
        items.append({"kind": "lightsail_static_ip", "id": s["name"], "name": "", "attrs": {"attached": bool(s.get("isAttached"))}})
    return items


COLLECTORS = (("ec2", _collect_ec2), ("opensearch", _collect_opensearch), ("rds", _collect_rds), ("lightsail", _collect_lightsail))


def collect_message(clients: Optional[Callable[[str], Any]] = None) -> str:
    """Read-only inventory snapshot as the JSON message ``parse`` consumes. One failing service
    (e.g. missing permission) is recorded in ``errors`` and never aborts the others."""
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or PRICE_TABLE_REGION
    factory = clients or _client_factory(region)
    items: List[Dict[str, Any]] = []
    errors: List[str] = []
    for name, fn in COLLECTORS:
        try:
            items.extend(fn(factory))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{name}: {type(exc).__name__}: {exc}"[:300])
    return json.dumps({"schema": SNAPSHOT_SCHEMA, "region": region, "items": items, "errors": errors})
