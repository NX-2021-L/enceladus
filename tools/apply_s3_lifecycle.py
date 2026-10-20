#!/usr/bin/env python3
"""Declarative, merge-preserving S3 lifecycle applier (ENC-PLN-100 / ENC-TSK-R18, R19, R20).

Generalizes the ENC-TSK-N49 precedent (tools/apply_rhythm_artifact_lifecycle.py).
The target buckets are NOT CloudFormation-managed (ruling P100-R16), so lifecycle is
applied from declarative specs in ``infrastructure/s3-lifecycle/<bucket>.json`` by a
gated workflow (.github/workflows/s3-lifecycle-apply.yml).

Safety invariants (enforced in code, covered by tools/test_apply_s3_lifecycle.py):

* MERGE-PRESERVING. PutBucketLifecycleConfiguration replaces the whole configuration, so
  every live rule whose ID does not start with ``enc-pln100-`` is carried over verbatim
  (ENC-TSK-Q20 / RhythmArtifact-* / adhoc-* and anything else). Only ``enc-pln100-*`` rules
  are added, replaced or (when dropped from the spec) removed. The tool refuses to run if
  the merge would drop or alter any unmanaged rule.
* AGENT-DOCUMENTS GUARD. No managed rule on ``jreese-net`` may match any key under
  ``agent-documents/``: explicit non-empty prefixes only, no tag-only / size-only / empty
  filter, and no prefix that is an ancestor or descendant of ``agent-documents/``.
* ``--plan`` and ``--verify`` are read-only; only ``--apply`` calls PutBucketLifecycleConfiguration.

Usage:
  python3 tools/apply_s3_lifecycle.py --validate
  python3 tools/apply_s3_lifecycle.py --plan   [--bucket all|<name>]
  python3 tools/apply_s3_lifecycle.py --apply  [--bucket all|<name>]
  python3 tools/apply_s3_lifecycle.py --verify [--bucket all|<name>]   # exit 1 on drift
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

MANAGED_ID_PREFIX = "enc-pln100-"
# Buckets with prefixes that must never be matched by a managed rule. A spec may add more
# via "protected_prefixes" but can never remove these.
PROTECTED_PREFIXES: Dict[str, Tuple[str, ...]] = {
    "jreese-net": ("agent-documents/",),
}
ALLOWED_ACTIONS = ("Expiration", "NoncurrentVersionExpiration", "AbortIncompleteMultipartUpload")
ALLOWED_FILTER_KEYS = ("Prefix", "Tag", "And", "ObjectSizeGreaterThan", "ObjectSizeLessThan")
DEFAULT_SPEC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "infrastructure", "s3-lifecycle")


class SpecError(ValueError):
    """Raised when a spec or merge violates a safety invariant."""


# --------------------------------------------------------------------------- helpers
def is_managed(rule: Dict[str, Any]) -> bool:
    return str(rule.get("ID", "")).startswith(MANAGED_ID_PREFIX)


def canonical(rule: Dict[str, Any]) -> str:
    return json.dumps(rule, sort_keys=True, separators=(",", ":"))


def filter_prefix(rule: Dict[str, Any]) -> Optional[str]:
    """Return the prefix a rule's filter is bounded by, or None when it is unbounded/empty."""
    flt = rule.get("Filter")
    if flt is None:
        pfx = rule.get("Prefix")  # legacy top-level prefix
    else:
        pfx = flt.get("Prefix")
        if pfx is None and isinstance(flt.get("And"), dict):
            pfx = flt["And"].get("Prefix")
    return pfx if pfx else None


def effective_protected(bucket: str, spec: Optional[Dict[str, Any]] = None) -> Tuple[str, ...]:
    extra = tuple((spec or {}).get("protected_prefixes") or ())
    return tuple(dict.fromkeys(PROTECTED_PREFIXES.get(bucket, ()) + extra))


def check_guard(bucket: str, rule: Dict[str, Any], protected: Tuple[str, ...]) -> None:
    """Refuse a managed rule whose filter could match a protected prefix."""
    if not protected:
        return
    pfx = filter_prefix(rule)
    rid = rule.get("ID")
    if pfx is None:
        raise SpecError(
            f"{bucket}: rule {rid!r} has an empty/absent prefix filter; protected prefixes "
            f"{list(protected)} require explicit non-empty prefixes only"
        )
    for pp in protected:
        if pp.startswith(pfx) or pfx.startswith(pp):
            raise SpecError(f"{bucket}: rule {rid!r} prefix {pfx!r} would match protected prefix {pp!r}")


def validate_rule(bucket: str, rule: Dict[str, Any], protected: Tuple[str, ...]) -> None:
    rid = rule.get("ID")
    if not isinstance(rid, str) or not rid.startswith(MANAGED_ID_PREFIX):
        raise SpecError(f"{bucket}: managed rule ID must start with {MANAGED_ID_PREFIX!r}: {rid!r}")
    if rule.get("Status") not in ("Enabled", "Disabled"):
        raise SpecError(f"{bucket}: rule {rid!r} Status must be Enabled or Disabled")
    flt = rule.get("Filter")
    if not isinstance(flt, dict) or not any(k in flt for k in ALLOWED_FILTER_KEYS):
        raise SpecError(f"{bucket}: rule {rid!r} needs an explicit Filter (use {{'Prefix': ''}} for bucket-wide)")
    bad = [k for k in flt if k not in ALLOWED_FILTER_KEYS]
    if bad:
        raise SpecError(f"{bucket}: rule {rid!r} unsupported Filter keys {bad}")
    extra = [k for k in rule if k not in ("ID", "Status", "Filter") + ALLOWED_ACTIONS]
    if extra:
        raise SpecError(f"{bucket}: rule {rid!r} unsupported keys {extra} (allowed actions: {list(ALLOWED_ACTIONS)})")
    if not any(a in rule for a in ALLOWED_ACTIONS):
        raise SpecError(f"{bucket}: rule {rid!r} has no action")
    exp = rule.get("Expiration") or {}
    if "ExpiredObjectDeleteMarker" in exp and len(exp) > 1:
        raise SpecError(f"{bucket}: rule {rid!r} Expiration cannot combine ExpiredObjectDeleteMarker with other keys")
    check_guard(bucket, rule, protected)


def validate_spec(spec: Dict[str, Any]) -> None:
    bucket = spec.get("bucket")
    if not isinstance(bucket, str) or not bucket:
        raise SpecError("spec missing 'bucket'")
    if not isinstance(spec.get("region"), str) or not spec["region"]:
        raise SpecError(f"{bucket}: spec missing 'region'")
    rules = spec.get("rules")
    if not isinstance(rules, list) or not rules:
        raise SpecError(f"{bucket}: spec 'rules' must be a non-empty list")
    protected = effective_protected(bucket, spec)
    seen = set()
    for rule in rules:
        validate_rule(bucket, rule, protected)
        if rule["ID"] in seen:
            raise SpecError(f"{bucket}: duplicate rule ID {rule['ID']!r}")
        seen.add(rule["ID"])


def load_specs(spec_dir: str, bucket: str = "all") -> List[Dict[str, Any]]:
    spec_dir = os.path.abspath(spec_dir)
    names = sorted(f for f in os.listdir(spec_dir) if f.endswith(".json"))
    specs = []
    for name in names:
        with open(os.path.join(spec_dir, name), encoding="utf-8") as fh:
            spec = json.load(fh)
        validate_spec(spec)
        if name != f"{spec['bucket']}.json":
            raise SpecError(f"{name}: file name must be <bucket>.json (bucket={spec['bucket']!r})")
        specs.append(spec)
    if bucket != "all":
        specs = [s for s in specs if s["bucket"] == bucket]
        if not specs:
            raise SpecError(f"no spec for bucket {bucket!r} in {spec_dir}")
    return specs


# --------------------------------------------------------------------------- merge / plan
def merge_rules(live_rules: List[Dict[str, Any]], spec_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Unmanaged live rules verbatim and in order, then the spec's managed rules in spec order."""
    unmanaged = [copy.deepcopy(r) for r in live_rules if not is_managed(r)]
    merged = unmanaged + [copy.deepcopy(r) for r in spec_rules]
    assert_unmanaged_preserved(live_rules, merged)
    return merged


def assert_unmanaged_preserved(live_rules: List[Dict[str, Any]], merged: List[Dict[str, Any]]) -> None:
    after = {canonical(r) for r in merged}
    for rule in live_rules:
        if not is_managed(rule) and canonical(rule) not in after:
            raise SpecError(f"merge would drop or alter unmanaged rule {rule.get('ID')!r}; refusing")
    # An unmanaged ID must never be reused by a managed rule and vice versa.
    live_unmanaged_ids = {r.get("ID") for r in live_rules if not is_managed(r)}
    for rule in merged:
        if is_managed(rule) and rule["ID"] in live_unmanaged_ids:
            raise SpecError(f"managed rule ID collides with unmanaged rule {rule['ID']!r}")


def compute_plan(live_rules: List[Dict[str, Any]], spec: Dict[str, Any]) -> Dict[str, Any]:
    validate_spec(spec)
    merged = merge_rules(live_rules, spec["rules"])
    live_by_id = {r.get("ID"): r for r in live_rules}
    spec_ids = {r["ID"] for r in spec["rules"]}
    actions: List[Tuple[str, str]] = []
    for r in live_rules:
        if not is_managed(r):
            actions.append(("KEEP", r.get("ID", "<no-id>")))
        elif r["ID"] not in spec_ids:
            actions.append(("REMOVE", r["ID"]))
    for r in spec["rules"]:
        old = live_by_id.get(r["ID"])
        if old is None:
            actions.append(("ADD", r["ID"]))
        elif canonical(old) != canonical(r):
            actions.append(("REPLACE", r["ID"]))
        else:
            actions.append(("UNCHANGED", r["ID"]))
    changed = any(a in ("ADD", "REPLACE", "REMOVE") for a, _ in actions)
    return {"merged": merged, "actions": actions, "changed": changed}


def compute_drift(live_rules: List[Dict[str, Any]], spec: Dict[str, Any]) -> List[Tuple[str, str]]:
    validate_spec(spec)
    live_managed = {r["ID"]: r for r in live_rules if is_managed(r)}
    drift: List[Tuple[str, str]] = []
    for r in spec["rules"]:
        old = live_managed.get(r["ID"])
        if old is None:
            drift.append(("MISSING", r["ID"]))
        elif canonical(old) != canonical(r):
            drift.append(("CHANGED", r["ID"]))
    spec_ids = {r["ID"] for r in spec["rules"]}
    drift.extend(("STALE", i) for i in live_managed if i not in spec_ids)
    return drift


# --------------------------------------------------------------------------- AWS I/O
def error_code(exc: Exception) -> str:
    return str(getattr(exc, "response", {}).get("Error", {}).get("Code", ""))


def make_client(region: str):  # pragma: no cover - thin boto3 wrapper
    import boto3

    return boto3.client("s3", region_name=region)


def fetch_live(s3, bucket: str) -> Dict[str, Any]:
    """Live config as {'Rules': [...], 'TransitionDefaultMinimumObjectSize': str|None}."""
    try:
        resp = s3.get_bucket_lifecycle_configuration(Bucket=bucket)
    except Exception as exc:  # noqa: BLE001
        if error_code(exc) == "NoSuchLifecycleConfiguration":
            return {"Rules": [], "TransitionDefaultMinimumObjectSize": None}
        raise
    return {
        "Rules": copy.deepcopy(resp.get("Rules") or []),
        "TransitionDefaultMinimumObjectSize": resp.get("TransitionDefaultMinimumObjectSize"),
    }


def put_merged(s3, bucket: str, merged: List[Dict[str, Any]], live: Dict[str, Any]) -> None:
    kwargs: Dict[str, Any] = {"Bucket": bucket, "LifecycleConfiguration": {"Rules": merged}}
    if live.get("TransitionDefaultMinimumObjectSize"):
        kwargs["TransitionDefaultMinimumObjectSize"] = live["TransitionDefaultMinimumObjectSize"]
    s3.put_bucket_lifecycle_configuration(**kwargs)


def run_bucket(spec: Dict[str, Any], mode: str, client_factory=make_client, out=print) -> int:
    """Execute one mode for one bucket spec. Returns 0 ok, 1 drift (verify) / error is raised."""
    bucket = spec["bucket"]
    s3 = client_factory(spec["region"])
    live = fetch_live(s3, bucket)
    out(f"[INFO] {bucket} ({spec['region']}): live rules={len(live['Rules'])} managed spec rules={len(spec['rules'])}")
    if mode == "verify":
        drift = compute_drift(live["Rules"], spec)
        for kind, rid in drift:
            out(f"  DRIFT {kind:8} {rid}")
        out(f"[{'ERROR' if drift else 'SUCCESS'}] {bucket}: verify {'drift=' + str(len(drift)) if drift else 'clean'}")
        return 1 if drift else 0
    plan = compute_plan(live["Rules"], spec)
    for action, rid in plan["actions"]:
        out(f"  {action:9} {rid}")
    if mode == "plan":
        out(f"[INFO] {bucket}: plan {'CHANGES' if plan['changed'] else 'no changes'} (rules after merge={len(plan['merged'])})")
        return 0
    if not plan["changed"]:
        out(f"[SUCCESS] {bucket}: apply no-op (already converged)")
        return 0
    put_merged(s3, bucket, plan["merged"], live)
    after = fetch_live(s3, bucket)
    missing_unmanaged = [r.get("ID") for r in live["Rules"] if not is_managed(r) and canonical(r) not in {canonical(x) for x in after["Rules"]}]
    drift = compute_drift(after["Rules"], spec)
    if missing_unmanaged or drift:
        raise SpecError(f"{bucket}: post-apply check failed unmanaged_missing={missing_unmanaged} drift={drift}")
    out(f"[SUCCESS] {bucket}: applied; rules now={len(after['Rules'])}")
    return 0


def main(argv=None, client_factory=make_client) -> int:
    parser = argparse.ArgumentParser(description="Merge-preserving declarative S3 lifecycle applier (ENC-PLN-100).")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--validate", action="store_true", help="validate specs offline (no AWS)")
    mode.add_argument("--plan", action="store_true", help="print diff against live; read-only; exit 0")
    mode.add_argument("--apply", action="store_true", help="merge and PutBucketLifecycleConfiguration")
    mode.add_argument("--verify", action="store_true", help="exit 1 if live managed rules drift from specs")
    parser.add_argument("--bucket", default="all", help="bucket name or 'all' (default)")
    parser.add_argument("--spec-dir", default=DEFAULT_SPEC_DIR)
    args = parser.parse_args(argv)
    chosen = "validate" if args.validate else "plan" if args.plan else "apply" if args.apply else "verify"
    try:
        specs = load_specs(args.spec_dir, args.bucket)
    except (SpecError, OSError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    if chosen == "validate":
        for s in specs:
            print(f"[SUCCESS] {s['bucket']}: spec valid ({len(s['rules'])} managed rules)")
        return 0
    rc = 0
    for spec in specs:
        try:
            rc |= run_bucket(spec, chosen, client_factory)
        except Exception as exc:  # noqa: BLE001
            print(f"[ERROR] {spec['bucket']}: {exc}", file=sys.stderr)
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
