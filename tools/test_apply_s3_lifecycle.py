"""Tests for apply_s3_lifecycle.py (ENC-PLN-100 / ENC-TSK-R18, R19, R20). Stubbed S3 client, no AWS."""

import copy
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import apply_s3_lifecycle as mod  # noqa: E402

Q20 = {"ID": "ENC-TSK-Q20-expire-x86_64-py3.11-artifacts", "Status": "Enabled",
       "Filter": {"Prefix": "lambda-artifacts/x86_64-py3.11/"}, "Expiration": {"Days": 30}}
RHYTHM = {"ID": "RhythmArtifact-sense", "Status": "Enabled",
          "Filter": {"Prefix": "gamma/rhythm-cycle/sense/"}, "Expiration": {"Days": 7}}
ROLLBACK = {"ID": "noncurrent-rollback-window", "Status": "Enabled", "Filter": {"Prefix": ""},
            "NoncurrentVersionExpiration": {"NoncurrentDays": 90}, "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7}}
LEGACY_DISABLED = {"ID": "legacy-off", "Status": "Disabled", "Prefix": "x/", "Expiration": {"Days": 1}}


def mobile_rule(days=7):
    return {"ID": "enc-pln100-mobile-noncurrent-7d", "Status": "Enabled", "Filter": {"Prefix": "mobile/"},
            "NoncurrentVersionExpiration": {"NoncurrentDays": days}}


def spec(bucket="jreese-net", rules=None, **extra):
    d = {"bucket": bucket, "region": "us-west-1", "rules": rules if rules is not None else [mobile_rule()]}
    d.update(extra)
    return d


class ClientError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class StubS3:
    def __init__(self, rules=None, tdmos=None, none=False):
        self.rules = copy.deepcopy(rules or [])
        self.tdmos = tdmos
        self.none = none or not rules
        self.puts = []

    def get_bucket_lifecycle_configuration(self, Bucket):
        if self.none:
            raise ClientError("NoSuchLifecycleConfiguration")
        out = {"Rules": copy.deepcopy(self.rules), "ResponseMetadata": {}}
        if self.tdmos:
            out["TransitionDefaultMinimumObjectSize"] = self.tdmos
        return out

    def put_bucket_lifecycle_configuration(self, **kw):
        self.puts.append(kw)
        self.rules = copy.deepcopy(kw["LifecycleConfiguration"]["Rules"])
        self.none = False


def run(s3, sp, mode):
    lines = []
    rc = mod.run_bucket(sp, mode, client_factory=lambda region: s3, out=lines.append)
    return rc, lines


# ---------------------------------------------------------------- merge preservation
def test_merge_preserves_unmanaged_rules_verbatim_and_in_order():
    live = [Q20, RHYTHM, ROLLBACK, LEGACY_DISABLED]
    merged = mod.merge_rules(copy.deepcopy(live), [mobile_rule()])
    assert merged[:4] == live
    assert merged[4] == mobile_rule()


def test_merge_replaces_stale_managed_rule_by_id_and_drops_removed_managed():
    stale = mobile_rule(days=30)
    gone = {"ID": "enc-pln100-obsolete", "Status": "Enabled", "Filter": {"Prefix": "z/"}, "Expiration": {"Days": 1}}
    plan = mod.compute_plan([Q20, stale, gone], spec())
    assert ("KEEP", Q20["ID"]) in plan["actions"]
    assert ("REPLACE", mobile_rule()["ID"]) in plan["actions"]
    assert ("REMOVE", "enc-pln100-obsolete") in plan["actions"]
    assert [r["ID"] for r in plan["merged"]] == [Q20["ID"], mobile_rule()["ID"]]
    assert plan["merged"][1]["NoncurrentVersionExpiration"]["NoncurrentDays"] == 7


def test_never_deletes_or_alters_unmanaged_even_when_it_overlaps_a_managed_id_space():
    with pytest.raises(mod.SpecError):
        mod.assert_unmanaged_preserved([Q20], [])
    altered = copy.deepcopy(Q20)
    altered["Expiration"]["Days"] = 1
    with pytest.raises(mod.SpecError):
        mod.assert_unmanaged_preserved([Q20], [altered])


def test_unmanaged_rule_matching_agent_documents_is_kept_not_an_error():
    wide = {"ID": "someone-elses-wide-rule", "Status": "Enabled", "Filter": {"Prefix": ""}, "Expiration": {"Days": 999}}
    plan = mod.compute_plan([wide], spec())
    assert plan["merged"][0] == wide


# ---------------------------------------------------------------- idempotency / apply
def test_apply_from_no_lifecycle_configuration_then_idempotent():
    s3 = StubS3(none=True)
    sp = spec(rules=[mobile_rule()])
    rc, lines = run(s3, sp, "apply")
    assert rc == 0 and len(s3.puts) == 1
    assert s3.puts[0]["LifecycleConfiguration"] == {"Rules": [mobile_rule()]}
    rc, lines = run(s3, sp, "apply")
    assert rc == 0 and len(s3.puts) == 1  # no second put
    assert any("no-op" in ln for ln in lines)
    assert run(s3, sp, "verify")[0] == 0


def test_apply_preserves_existing_and_passes_transition_min_size_through():
    s3 = StubS3([Q20, RHYTHM], tdmos="all_storage_classes_128K")
    rc, _ = run(s3, spec(), "apply")
    assert rc == 0
    put = s3.puts[0]
    assert put["TransitionDefaultMinimumObjectSize"] == "all_storage_classes_128K"
    assert put["LifecycleConfiguration"]["Rules"][:2] == [Q20, RHYTHM]


def test_plan_is_read_only_and_exit_zero_with_changes():
    s3 = StubS3([Q20])
    rc, lines = run(s3, spec(), "plan")
    assert rc == 0 and s3.puts == []
    assert any(ln.strip().startswith("ADD") for ln in lines)
    assert mod.main(["--plan", "--bucket", "nope-bucket"], client_factory=lambda r: s3) == 1


def test_main_apply_runs_every_spec_with_stub(tmp_path):
    import json
    (tmp_path / "jreese-net.json").write_text(json.dumps(spec()))
    s3 = StubS3([Q20])
    assert mod.main(["--apply", "--spec-dir", str(tmp_path)], client_factory=lambda r: s3) == 0
    assert mod.main(["--verify", "--spec-dir", str(tmp_path)], client_factory=lambda r: s3) == 0


# ---------------------------------------------------------------- drift
def test_verify_reports_missing_changed_and_stale_with_exit_one():
    sp = spec()
    assert run(StubS3([Q20]), sp, "verify")[0] == 1                       # missing
    assert run(StubS3([Q20, mobile_rule(days=30)]), sp, "verify")[0] == 1  # changed
    stale = {"ID": "enc-pln100-obsolete", "Status": "Enabled", "Filter": {"Prefix": "z/"}, "Expiration": {"Days": 1}}
    assert run(StubS3([mobile_rule(), stale]), sp, "verify")[0] == 1       # stale
    assert run(StubS3([Q20, mobile_rule()]), sp, "verify")[0] == 0         # clean
    assert mod.compute_drift([mobile_rule()], sp) == []


def test_verify_with_no_lifecycle_configuration_is_drift():
    assert run(StubS3(none=True), spec(), "verify")[0] == 1


# ---------------------------------------------------------------- agent-documents guard
@pytest.mark.parametrize("flt", [
    {"Prefix": ""},
    {"Prefix": "agent-documents/"},
    {"Prefix": "agent-documents/sub/"},
    {"Prefix": "agent-"},
    {"Prefix": "a"},
    {"Tag": {"Key": "k", "Value": "v"}},
    {"And": {"Tags": [{"Key": "k", "Value": "v"}]}},
    {"ObjectSizeGreaterThan": 1},
])
def test_jreese_net_guard_refuses_filters_that_could_match_agent_documents(flt):
    rule = {"ID": "enc-pln100-bad", "Status": "Enabled", "Filter": flt, "NoncurrentVersionExpiration": {"NoncurrentDays": 7}}
    with pytest.raises(mod.SpecError):
        mod.validate_spec(spec(rules=[rule]))
    with pytest.raises(mod.SpecError):
        mod.compute_plan([], spec(rules=[rule]))


def test_jreese_net_guard_allows_explicit_non_overlapping_prefixes():
    for p in ("mobile/", "governance/cost-digest/", "lambda-artifacts/arm64-py3.12/", "agent-scratch/"):
        rule = {"ID": "enc-pln100-ok", "Status": "Enabled", "Filter": {"Prefix": p}, "NoncurrentVersionExpiration": {"NoncurrentDays": 7}}
        mod.validate_spec(spec(rules=[rule]))


def test_spec_can_add_protected_prefixes_and_other_buckets_allow_bucket_wide():
    wide = {"ID": "enc-pln100-bucket-wide", "Status": "Enabled", "Filter": {"Prefix": ""},
            "NoncurrentVersionExpiration": {"NoncurrentDays": 30, "NewerNoncurrentVersions": 10}}
    mod.validate_spec(spec(bucket="enceladus-ui-v2", rules=[wide]))
    with pytest.raises(mod.SpecError):
        mod.validate_spec(spec(bucket="enceladus-ui-v2", rules=[wide], protected_prefixes=["keep/"]))


# ---------------------------------------------------------------- spec validation
def test_managed_rule_ids_must_use_enc_pln100_prefix():
    rule = mobile_rule()
    rule["ID"] = "ENC-TSK-Q20-sneaky"
    with pytest.raises(mod.SpecError):
        mod.validate_spec(spec(rules=[rule]))


def test_spec_rejects_unsupported_actions_duplicates_and_missing_filter():
    t = {"ID": "enc-pln100-t", "Status": "Enabled", "Filter": {"Prefix": "t/"}, "Transitions": [{"Days": 1, "StorageClass": "GLACIER"}]}
    with pytest.raises(mod.SpecError):
        mod.validate_spec(spec(rules=[t]))
    with pytest.raises(mod.SpecError):
        mod.validate_spec(spec(rules=[mobile_rule(), mobile_rule()]))
    nf = mobile_rule()
    del nf["Filter"]
    with pytest.raises(mod.SpecError):
        mod.validate_spec(spec(rules=[nf]))


# ---------------------------------------------------------------- committed specs
def test_all_committed_specs_validate_and_only_use_managed_ids():
    specs = mod.load_specs(mod.DEFAULT_SPEC_DIR)
    assert specs, "no specs committed"
    assert "jreese-net" in {s["bucket"] for s in specs}
    for s in specs:
        for r in s["rules"]:
            assert r["ID"].startswith(mod.MANAGED_ID_PREFIX)
            if s["bucket"] == "jreese-net":
                p = mod.filter_prefix(r)
                assert p and not p.startswith("agent-documents/") and not "agent-documents/".startswith(p)
