#!/usr/bin/env python3
"""Self-tests for tools/verify_arm64_validation_harness.py (ENC-TSK-O88).

No AWS credentials or network access required -- every AWS client is a
minimal fake. The tests that matter most are named ``*_unknown_not_pass_*``:
they prove that when a probe cannot run (permission denied, no probe
registered, dependency unavailable), the harness reports UNKNOWN, never a
fabricated PASS. This is the exact defect class this whole task exists to
close (ENC-ISS-651's empty-lookup false clears, DVP-ISS-103's 200-with-nothing-
written health probe).

Run directly:
    python3 tools/verify_arm64_validation_harness.py --self-test
or:
    python3 -m pytest tools/test_verify_arm64_validation_harness.py -v
"""

from __future__ import annotations

import base64
import hashlib
import sys
import time
import zipfile
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import verify_arm64_validation_harness as harness  # noqa: E402


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class FakeBody:
    def __init__(self, data: bytes):
        self._data = data

    def read(self) -> bytes:
        return self._data


class FakeLambdaClient:
    def __init__(self, *, config=None, config_error=None, invoke_error=None,
                 invoke_response=None, layer_versions=None, layer_error=None,
                 get_function_response=None, get_function_error=None):
        self._config = config or {}
        self._config_error = config_error
        self._invoke_error = invoke_error
        self._invoke_response = invoke_response
        self._layer_versions = layer_versions or {}
        self._layer_error = layer_error
        self._get_function_response = get_function_response
        self._get_function_error = get_function_error

    def get_function(self, FunctionName):  # noqa: N803
        # Deliberately raises when unconfigured: a fake that silently returned
        # an empty dict would let the substitute path look exercised in tests
        # that never set it up.
        if self._get_function_error:
            raise self._get_function_error
        if self._get_function_response is None:
            raise AttributeError("get_function not configured on this fake")
        return self._get_function_response

    def get_function_configuration(self, FunctionName):  # noqa: N803 - matches boto3 signature style
        if self._config_error:
            raise self._config_error
        return self._config

    def invoke(self, FunctionName, Payload):  # noqa: N803
        if self._invoke_error:
            raise self._invoke_error
        return self._invoke_response

    def get_layer_version(self, LayerName, VersionNumber):  # noqa: N803
        if self._layer_error:
            raise self._layer_error
        return self._layer_versions[(LayerName, VersionNumber)]


class FakeS3Client:
    def __init__(self, *, objects=None, get_error=None):
        self._objects = objects or {}
        self._get_error = get_error

    def get_object(self, Bucket, Key):  # noqa: N803
        if self._get_error:
            raise self._get_error
        return {"Body": FakeBody(self._objects[(Bucket, Key)])}


class FakeCloudWatchLogs:
    """filter_log_events/describe_log_streams fake matching real CloudWatch
    Logs semantics closely enough for the point-4 probe (ENC-TSK-P08):
    filter_log_events only returns events within [startTime, endTime), same
    as the real API -- this is what makes the run-start-anchoring tests
    meaningful rather than trivially true.

    `sequence`, when given, is a list of event-lists consumed one per call to
    filter_log_events (the last entry repeats once exhausted) -- used to
    simulate the bounded-poll-and-retry remedy seeing an invocation terminate
    partway through polling.
    """

    def __init__(self, events=None, *, has_ever_run=True, describe_error=None,
                 filter_error=None, sequence=None):
        self._events = events or []
        self._has_ever_run = has_ever_run
        self._describe_error = describe_error
        self._filter_error = filter_error
        self._sequence = sequence
        self._call_n = 0

    def filter_log_events(self, logGroupName, startTime, endTime, limit=1000, nextToken=None):  # noqa: N803
        if self._filter_error:
            raise self._filter_error
        if self._sequence is not None:
            idx = min(self._call_n, len(self._sequence) - 1)
            events = self._sequence[idx]
            self._call_n += 1
        else:
            events = self._events
        matched = [e for e in events if startTime <= e["timestamp"] < endTime]
        return {"events": matched}

    def describe_log_streams(self, logGroupName, limit=1, **kwargs):  # noqa: N803
        if self._describe_error:
            raise self._describe_error
        return {"logStreams": [{"logStreamName": "s1"}] if self._has_ever_run else []}


def _zip_bytes(files: dict) -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Point 1 -- artifact identity
# ---------------------------------------------------------------------------

def test_point1_pass_when_digest_matches():
    body = b"fake-zip-bytes"
    digest = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
    lam = FakeLambdaClient(config={"Architectures": ["arm64"], "CodeSha256": digest})
    s3 = FakeS3Client(objects={("bkt", "lambda-artifacts/arm64-py3.12/fn-abc123.zip"): body})
    result = harness.check_artifact_identity(lam, s3, "fn", "arm64", "3.12", "abc123", bucket="bkt",
                                             artifact_basename="fn")
    assert result.state == harness.PASS


def test_point1_fail_on_digest_mismatch():
    lam = FakeLambdaClient(config={"Architectures": ["arm64"], "CodeSha256": "wrong-digest"})
    s3 = FakeS3Client(objects={("bkt", "lambda-artifacts/arm64-py3.12/fn-abc123.zip"): b"other-bytes"})
    result = harness.check_artifact_identity(lam, s3, "fn", "arm64", "3.12", "abc123", bucket="bkt",
                                             artifact_basename="fn")
    assert result.state == harness.FAIL


def test_point1_fail_on_wrong_architecture():
    lam = FakeLambdaClient(config={"Architectures": ["x86_64"], "CodeSha256": "irrelevant"})
    s3 = FakeS3Client()
    result = harness.check_artifact_identity(lam, s3, "fn", "arm64", "3.12", "abc123",
                                             artifact_basename="fn")
    assert result.state == harness.FAIL
    assert "not even the right build target" in result.detail


def test_point1_unknown_not_pass_when_no_commit_sha_given():
    lam = FakeLambdaClient(config={"Architectures": ["arm64"], "CodeSha256": "x"})
    s3 = FakeS3Client()
    result = harness.check_artifact_identity(lam, s3, "fn", "arm64", "3.12", commit_sha=None)
    assert result.state == harness.UNKNOWN


def test_point1_unknown_not_pass_when_s3_access_denied():
    lam = FakeLambdaClient(config={"Architectures": ["arm64"], "CodeSha256": "x"})
    s3 = FakeS3Client(get_error=Exception("AccessDenied: not authorized to perform: s3:GetObject"))
    result = harness.check_artifact_identity(lam, s3, "fn", "arm64", "3.12", "abc123",
                                             artifact_basename="fn")
    assert result.state == harness.UNKNOWN
    assert "denied" in result.detail.lower()
    assert result.reason_code == "permission_denied", (
        "an IAM denial must carry the machine-readable permission_denied code, not just prose, "
        "so a fleet-wide aggregator can distinguish it from every other kind of unknown"
    )


def test_point1_unknown_not_pass_when_config_read_fails():
    lam = FakeLambdaClient(config_error=Exception("Throttled"))
    s3 = FakeS3Client()
    result = harness.check_artifact_identity(lam, s3, "fn", "arm64", "3.12", "abc123",
                                             artifact_basename="fn")
    assert result.state == harness.UNKNOWN


# ---------------------------------------------------------------------------
# Point 2 -- layer coherence
# ---------------------------------------------------------------------------

def test_point2_pass_when_zero_layers():
    lam = FakeLambdaClient(config={"Architectures": ["arm64"], "Layers": []})
    result = harness.check_layer_coherence(lam, "auth-refresh", downloader=lambda url: b"", classify_so=lambda p: None)
    assert result.state == harness.PASS
    assert "zero layers" in result.detail


def test_point2_pass_when_layer_is_pure_python_regardless_of_metadata():
    layer_zip = _zip_bytes({"python/enceladus_shared/__init__.py": "x = 1\n"})
    lam = FakeLambdaClient(
        config={"Architectures": ["arm64"],
                "Layers": [{"Arn": "arn:aws:lambda:us-west-2:1:layer:enceladus-shared:10"}]},
        layer_versions={("enceladus-shared", 10): {
            "CompatibleArchitectures": None,  # metadata says nothing -- must not matter
            "Content": {"Location": "https://example/layer10.zip"},
        }},
    )
    result = harness.check_layer_coherence(
        lam, "fn", downloader=lambda url: layer_zip, classify_so=lambda p: None,
    )
    assert result.state == harness.PASS
    assert "zero .so files" in result.detail


def test_point2_fail_on_mismatched_compiled_object_even_with_compatible_metadata():
    layer_zip = _zip_bytes({"python/lib/_native.so": "binary-ish"})
    lam = FakeLambdaClient(
        config={"Architectures": ["arm64"],
                "Layers": [{"Arn": "arn:aws:lambda:us-west-2:1:layer:some-layer:3"}]},
        layer_versions={("some-layer", 3): {
            "CompatibleArchitectures": ["arm64"],  # metadata LIES -- inspection must catch it
            "Content": {"Location": "https://example/layer3.zip"},
        }},
    )
    result = harness.check_layer_coherence(
        lam, "fn", downloader=lambda url: layer_zip, classify_so=lambda p: "x86_64",
    )
    assert result.state == harness.FAIL
    assert "CompatibleArchitectures metadata" in result.detail


def test_point2_unknown_not_pass_when_get_layer_version_denied():
    lam = FakeLambdaClient(
        config={"Architectures": ["arm64"],
                "Layers": [{"Arn": "arn:aws:lambda:us-west-2:1:layer:some-layer:3"}]},
        layer_error=Exception("AccessDeniedException"),
    )
    result = harness.check_layer_coherence(lam, "fn", downloader=lambda url: b"", classify_so=lambda p: None)
    assert result.state == harness.UNKNOWN


def test_point2_unknown_not_pass_when_download_fails():
    lam = FakeLambdaClient(
        config={"Architectures": ["arm64"],
                "Layers": [{"Arn": "arn:aws:lambda:us-west-2:1:layer:some-layer:3"}]},
        layer_versions={("some-layer", 3): {
            "CompatibleArchitectures": ["arm64"],
            "Content": {"Location": "https://example/layer3.zip"},
        }},
    )

    def _boom(url):
        raise Exception("connection reset")

    result = harness.check_layer_coherence(lam, "fn", downloader=_boom, classify_so=lambda p: None)
    assert result.state == harness.UNKNOWN


# ---------------------------------------------------------------------------
# Point 3 -- live invocation
# ---------------------------------------------------------------------------

def test_point3_pass_on_clean_invoke():
    lam = FakeLambdaClient(invoke_response={"StatusCode": 200, "Payload": FakeBody(b"{}")})
    result = harness.check_live_invocation(lam, "fn")
    assert result.state == harness.PASS


def test_point3_fail_on_function_error():
    lam = FakeLambdaClient(invoke_response={
        "StatusCode": 200, "FunctionError": "Unhandled",
        "Payload": FakeBody(b'{"errorType": "ModuleNotFoundError"}'),
    })
    result = harness.check_live_invocation(lam, "fn")
    assert result.state == harness.FAIL


def test_point3_unknown_not_pass_when_invoke_denied():
    lam = FakeLambdaClient(invoke_error=Exception(
        "An error occurred (AccessDeniedException) when calling the Invoke operation: "
        "User: ... is not authorized to perform: lambda:InvokeFunction"
    ))
    result = harness.check_live_invocation(lam, "fn")
    assert result.state == harness.UNKNOWN, "IAM denial must be unknown, never a fabricated pass"
    assert result.reason_code == "permission_denied"


def test_point3_fail_when_function_does_not_exist():
    lam = FakeLambdaClient(invoke_error=Exception("ResourceNotFoundException: Function not found"))
    result = harness.check_live_invocation(lam, "fn")
    assert result.state == harness.FAIL


# ---------------------------------------------------------------------------
# Point 4 -- integration edge
# ---------------------------------------------------------------------------

def test_point4_unknown_not_pass_when_no_probe_registered():
    result = harness.check_integration_edge("some-function-with-no-probe-xyz", {})
    assert result.state == harness.UNKNOWN
    assert "no integration probe registered" in result.detail
    assert result.reason_code == "no_probe_registered", (
        "must be distinguishable from permission_denied -- these are different failure classes "
        "and an aggregator must not have to parse prose to tell them apart"
    )


def test_point4_uses_registered_probe_result():
    harness.PROBE_REGISTRY["_test_probe_fn"] = lambda fn, clients: (harness.PASS, "ok")
    try:
        result = harness.check_integration_edge("_test_probe_fn", {})
        assert result.state == harness.PASS
    finally:
        del harness.PROBE_REGISTRY["_test_probe_fn"]


def test_point4_unknown_not_pass_when_probe_raises():
    def _boom(fn, clients):
        raise RuntimeError("probe blew up")

    harness.PROBE_REGISTRY["_test_probe_fn2"] = _boom
    try:
        result = harness.check_integration_edge("_test_probe_fn2", {})
        assert result.state == harness.UNKNOWN
    finally:
        del harness.PROBE_REGISTRY["_test_probe_fn2"]


def test_governance_mart_probe_fail_on_stale_schedule():
    # ENC-TSK-P08: rewritten for the log-group-wide, run-start-anchored probe
    # (filter_log_events, not describe_log_streams(limit=1)). The log group
    # has run before (has_ever_run=True) but nothing shows up inside the
    # schedule window predating this run -- genuine staleness.
    logs = FakeCloudWatchLogs(events=[], has_ever_run=True)
    run_start_ms = 1_700_000_000_000.0
    state, detail = harness._probe_governance_mart_schedule(
        "devops-recompute-governance", {"logs": logs, "run_start_ms": run_start_ms})
    assert state == harness.FAIL
    assert "schedule window" in detail


# ---------------------------------------------------------------------------
# Point 5 -- CI predicate observed failing
# ---------------------------------------------------------------------------

def test_point5_fail_when_negative_control_test_missing():
    result = harness.check_ci_predicate_observed_failing(negative_control_test="tools/does_not_exist_xyz.py")
    assert result.state == harness.FAIL


def test_point5_unknown_not_pass_when_gh_unavailable(tmp_path):
    fake_test = tmp_path / "test_fake.py"
    fake_test.write_text("def test_negative_case():\n    assert True\n")

    def fake_pytest(*args, **kwargs):
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    result = harness.check_ci_predicate_observed_failing(
        negative_control_test=str(fake_test.relative_to(harness.REPO_ROOT))
        if fake_test.is_relative_to(harness.REPO_ROOT) else str(fake_test),
        run_pytest=fake_pytest,
        which=lambda name: None,  # gh not installed
    )
    assert result.state == harness.UNKNOWN
    assert "gh CLI not available" in result.detail


def test_point5_fail_when_local_negative_control_does_not_pass(tmp_path):
    fake_test = tmp_path / "test_fake2.py"
    fake_test.write_text("def test_negative_case():\n    assert False\n")

    def fake_pytest(*args, **kwargs):
        return SimpleNamespace(returncode=1, stdout="1 failed", stderr="")

    result = harness.check_ci_predicate_observed_failing(
        negative_control_test=str(fake_test), run_pytest=fake_pytest, which=lambda name: None,
    )
    assert result.state == harness.FAIL


def test_point5_pass_when_ci_history_shows_the_step_red(tmp_path):
    fake_test = tmp_path / "test_fake3.py"
    fake_test.write_text("def test_negative_case():\n    assert True\n")

    def fake_pytest(*args, **kwargs):
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    calls = {"n": 0}

    def fake_gh(cmd, **kwargs):
        calls["n"] += 1
        if cmd[1:3] == ["run", "list"]:
            return SimpleNamespace(returncode=0, stdout='[{"databaseId": 42}]', stderr="")
        if cmd[1:3] == ["run", "view"]:
            return SimpleNamespace(returncode=0, stdout="FAIL Verify Lambda architecture parity", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="unexpected")

    result = harness.check_ci_predicate_observed_failing(
        negative_control_test=str(fake_test), run_pytest=fake_pytest, run_gh=fake_gh,
        which=lambda name: "/usr/bin/gh",
    )
    assert result.state == harness.PASS
    assert calls["n"] == 2


def test_point5_unknown_not_pass_when_no_failed_runs_found(tmp_path):
    fake_test = tmp_path / "test_fake4.py"
    fake_test.write_text("def test_negative_case():\n    assert True\n")

    def fake_pytest(*args, **kwargs):
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def fake_gh(cmd, **kwargs):
        return SimpleNamespace(returncode=0, stdout="[]", stderr="")

    result = harness.check_ci_predicate_observed_failing(
        negative_control_test=str(fake_test), run_pytest=fake_pytest, run_gh=fake_gh,
        which=lambda name: "/usr/bin/gh",
    )
    assert result.state == harness.UNKNOWN
    assert "not been observed red" in result.detail


# ---------------------------------------------------------------------------
# Aggregation (FunctionReport.overall) -- unknown is non-passing
# ---------------------------------------------------------------------------

def test_overall_is_fail_if_any_point_fails():
    report = harness.FunctionReport(function_name="fn", points=[
        harness.PointResult(1, "a", harness.PASS, ""),
        harness.PointResult(2, "b", harness.FAIL, ""),
        harness.PointResult(3, "c", harness.UNKNOWN, ""),
    ])
    assert report.overall == harness.FAIL


def test_overall_is_unknown_not_pass_when_any_point_unknown_and_none_fail():
    report = harness.FunctionReport(function_name="fn", points=[
        harness.PointResult(1, "a", harness.PASS, ""),
        harness.PointResult(2, "b", harness.PASS, ""),
        harness.PointResult(3, "c", harness.UNKNOWN, ""),
        harness.PointResult(4, "d", harness.PASS, ""),
        harness.PointResult(5, "e", harness.PASS, ""),
    ])
    assert report.overall == harness.UNKNOWN, "a single unrunnable point must sink the whole verdict, not be absorbed into a pass"


def test_overall_is_pass_only_when_all_five_points_pass():
    report = harness.FunctionReport(function_name="fn", points=[
        harness.PointResult(i, f"p{i}", harness.PASS, "") for i in range(1, 6)
    ])
    assert report.overall == harness.PASS


def test_point_result_rejects_invalid_state():
    with pytest.raises(ValueError):
        harness.PointResult(1, "a", "vacuous-pass", "")


def test_point_result_rejects_unregistered_reason_code():
    with pytest.raises(ValueError):
        harness.PointResult(1, "a", harness.UNKNOWN, "", reason_code="made_up_code_xyz")


# ---------------------------------------------------------------------------
# The machine-readable reason_code contract itself (per coordinator review of
# ENC-TSK-O88): "unknown" alone conflates "IAM cannot see the answer" with
# "no probe was ever written" with "gh is not installed." A downstream
# aggregator (ENC-TSK-O89 across 26 functions, ENC-TSK-O90 across Category A)
# must be able to tell these apart from JSON alone, without a human reading
# `detail` prose. These tests prove that contract, and that it is distinct
# from (in addition to, not instead of) the pass/fail/unknown state itself.
# ---------------------------------------------------------------------------

def test_permission_denied_is_a_distinct_reason_code_from_other_unknowns():
    """The two operationally critical unknowns (IAM denial vs. no probe
    registered) must carry different reason codes even though both are
    state=unknown. Confusing them would hide exactly the fleet/IAM fact
    ENC-PLN-086 Wave 4 needs to see: two of five points are structurally
    blocked under AWS_PROFILE=enceladus-agent, and that is not the same
    kind of gap as 'nobody wrote a probe yet.'"""
    denied = harness.check_live_invocation(
        FakeLambdaClient(invoke_error=Exception("AccessDeniedException: not authorized to perform: lambda:InvokeFunction")),
        "fn",
    )
    no_probe = harness.check_integration_edge("fn-with-no-probe", {})
    assert denied.state == harness.UNKNOWN
    assert no_probe.state == harness.UNKNOWN
    assert denied.reason_code == "permission_denied"
    assert no_probe.reason_code == "no_probe_registered"
    assert denied.reason_code != no_probe.reason_code


def test_function_report_surfaces_permission_denied_points_for_aggregation():
    """FunctionReport.permission_denied_points (and its JSON mirror) is the
    concrete aggregation surface: an O89/O90 rollup across dozens of
    functions can group on this without re-parsing prose per function."""
    report = harness.FunctionReport(function_name="fn", points=[
        harness.PointResult(1, "artifact_identity", harness.UNKNOWN, "", reason_code="permission_denied"),
        harness.PointResult(2, "layer_coherence", harness.PASS, "", reason_code="zero_layers"),
        harness.PointResult(3, "live_invocation", harness.UNKNOWN, "", reason_code="permission_denied"),
        harness.PointResult(4, "integration_edge", harness.UNKNOWN, "", reason_code="no_probe_registered"),
        harness.PointResult(5, "ci_predicate_observed_failing", harness.PASS, "", reason_code="ci_history_confirmed_red"),
    ])
    assert report.permission_denied_points == [1, 3]
    assert report.overall == harness.UNKNOWN
    as_json = report.to_dict()
    assert as_json["permission_denied_points"] == [1, 3]
    assert as_json["overall"] == "unknown", (
        "a report with 2 of 5 points blocked purely by IAM must never serialize as anything "
        "that could be mistaken for a pass -- 'mostly fine' is not a state this contract has"
    )


def test_unknown_and_pass_are_never_ambiguous_in_serialized_output():
    """Guards the exact failure mode named in review: a run where points are
    unknown must not 'read as mostly fine.' overall is a plain string, not a
    score or a percentage, and it must differ for an all-pass report vs. one
    with any unknown -- verified at the to_dict() boundary that O89 actually
    consumes, not just on the Python property."""
    all_pass = harness.FunctionReport(function_name="fn", points=[
        harness.PointResult(i, f"p{i}", harness.PASS, "", reason_code="digest_match" if i == 1 else "unspecified")
        for i in range(1, 6)
    ]).to_dict()
    one_unknown = harness.FunctionReport(function_name="fn", points=[
        harness.PointResult(1, "p1", harness.PASS, "", reason_code="digest_match"),
        harness.PointResult(2, "p2", harness.PASS, "", reason_code="zero_layers"),
        harness.PointResult(3, "p3", harness.UNKNOWN, "", reason_code="permission_denied"),
        harness.PointResult(4, "p4", harness.PASS, "", reason_code="probe_result"),
        harness.PointResult(5, "p5", harness.PASS, "", reason_code="ci_history_confirmed_red"),
    ]).to_dict()
    assert all_pass["overall"] == "pass"
    assert one_unknown["overall"] == "unknown"
    assert all_pass["overall"] != one_unknown["overall"]


# ---------------------------------------------------------------------------
# Point 1 -- deployed-package SUBSTITUTE (ENC-TSK-O96 / ENC-ISS-658)
#
# The s3:GetObject grant point 1 was written against was WITHDRAWN, not
# delayed: granting it means editing the NotResource Deny that is the S3
# security boundary for every agent session (ENC-ISS-659). These tests pin the
# substitute that replaces it, and above all pin what it must never do.
# ---------------------------------------------------------------------------

_DENIED = Exception("AccessDenied: not authorized to perform: s3:GetObject")


def _fake_classifier(mapping: dict):
    """classify_so stand-in keyed by file name. Real ELF classification is
    verify_lambda_package_arch.py's own tested concern -- borrowing it here
    would test that module, not this one, and would need real binaries."""
    return lambda path: mapping.get(path.name)


def _lambda_with_package(files: dict, *, arch="arm64", sha=None):
    """A fake whose GetFunction presigned package really hashes to the
    CodeSha256 it reports -- the substitute refuses to inspect bytes it cannot
    attribute, so a fake that skipped this would exercise nothing."""
    body = _zip_bytes(files)
    digest = sha or base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
    lam = FakeLambdaClient(
        config={"Architectures": [arch], "CodeSha256": digest},
        get_function_response={"Code": {"Location": "https://presigned.example/pkg.zip"},
                               "Configuration": {"CodeSha256": digest}},
    )
    return lam, body


def test_substitute_turns_a_blind_denial_into_a_real_fail():
    """The whole point of the substitute: an x86_64 object in the DEPLOYED
    package is conclusive on its own and needs no S3 read to be true."""
    lam, body = _lambda_with_package({"pyarrow/lib.so": b"ELF"})
    result = harness.check_artifact_identity(
        lam, FakeS3Client(get_error=_DENIED), "fn", "arm64", "3.12", "abc123", artifact_basename="fn",
        downloader=lambda url: body,
        classify_so=_fake_classifier({"lib.so": "x86_64"}))
    assert result.state == harness.FAIL
    assert result.reason_code == "deployed_package_arch_mismatch"
    assert result.substitute["state"] == harness.FAIL


def test_substitute_never_upgrades_an_unknown_to_pass():
    """Every non-failing substitute branch. None may pass: inspecting what is
    deployed says nothing about whether it came from the arm64 BUILD."""
    clean, body = _lambda_with_package({"handler.py": b"x", "native.so": b"ELF"})
    pure, pure_body = _lambda_with_package({"handler.py": b"x"})
    unclassifiable, unc_body = _lambda_with_package({"weird.so": b"???"})
    cases = [
        (clean, lambda u: body, {"native.so": "arm64"}, "deployed_package_arch_consistent"),
        (pure, lambda u: pure_body, {}, "deployed_package_no_native_objects"),
        (unclassifiable, lambda u: unc_body, {"weird.so": None}, "deployed_package_unclassifiable"),
        (FakeLambdaClient(config={"Architectures": ["arm64"], "CodeSha256": "x"},
                          get_function_error=Exception("AccessDeniedException")),
         lambda u: b"", {}, "deployed_package_unavailable"),
    ]
    for lam, dl, mapping, expected_reason in cases:
        result = harness.check_artifact_identity(
            lam, FakeS3Client(get_error=_DENIED), "fn", "arm64", "3.12", "abc123",
            downloader=dl, classify_so=_fake_classifier(mapping))
        assert result.state != harness.PASS, f"{expected_reason} must never pass"
        assert result.substitute["reason_code"] == expected_reason
        assert result.substitute["state"] == harness.UNKNOWN


def test_substitute_refuses_to_inspect_bytes_it_cannot_attribute():
    """A download that does not hash to the deployed CodeSha256 is an
    unattributed blob. Anything found in it is evidence about nothing."""
    lam, _ = _lambda_with_package({"native.so": b"ELF"})
    result = harness.check_artifact_identity(
        lam, FakeS3Client(get_error=_DENIED), "fn", "arm64", "3.12", "abc123", artifact_basename="fn",
        downloader=lambda url: b"different-bytes-entirely",
        classify_so=_fake_classifier({"native.so": "x86_64"}))
    assert result.substitute["reason_code"] == "deployed_package_digest_unverified"
    assert result.state == harness.UNKNOWN, (
        "wrong-arch objects in unattributed bytes must NOT produce a fail either -- "
        "the subject of the check is unproven in both directions")


def test_substitute_does_not_erase_the_permission_denied_aggregation():
    """ENC-TSK-O89 and O90 group 26+ functions on permission_denied_points.
    An inconclusive substitute must leave the point's own reason_code alone,
    or the IAM fact those consumers count silently becomes a probe gap."""
    lam, body = _lambda_with_package({"handler.py": b"x"})
    result = harness.check_artifact_identity(
        lam, FakeS3Client(get_error=_DENIED), "fn", "arm64", "3.12", "abc123", artifact_basename="fn",
        downloader=lambda url: body, classify_so=_fake_classifier({}))
    assert result.reason_code == "permission_denied"
    report = harness.FunctionReport(function_name="fn", points=[result])
    assert report.permission_denied_points == [1]
    assert report.to_dict()["points"][0]["substitute"]["reason_code"] == "deployed_package_no_native_objects"


def test_substitute_also_runs_when_no_commit_sha_was_supplied():
    """Without a commit sha the S3 key cannot even be resolved -- O89 runs
    across 26 twins where per-function shas are not all known. The substitute
    still finds a wrong-arch package."""
    lam, body = _lambda_with_package({"native.so": b"ELF"})
    result = harness.check_artifact_identity(
        lam, FakeS3Client(), "fn", "arm64", "3.12", commit_sha=None,
        downloader=lambda url: body,
        classify_so=_fake_classifier({"native.so": "x86_64"}))
    assert result.state == harness.FAIL


def test_point_result_structurally_forbids_a_passing_substitute():
    """Enforced by the type, not by convention -- a future edit that tries to
    promote substitute evidence to PASS fails loudly at construction."""
    with pytest.raises(ValueError, match="never report PASS"):
        harness.PointResult(1, "artifact_identity", harness.UNKNOWN, "",
                            reason_code="permission_denied",
                            substitute={"state": harness.PASS,
                                        "reason_code": "deployed_package_arch_consistent",
                                        "detail": ""})


def test_primary_s3_path_still_passes_and_is_unaffected():
    """The substitute must not disturb the one path that CAN prove provenance:
    a real artifact read still passes, with no substitute attached."""
    body = b"fake-zip-bytes"
    digest = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
    lam = FakeLambdaClient(config={"Architectures": ["arm64"], "CodeSha256": digest})
    s3 = FakeS3Client(objects={("bkt", "lambda-artifacts/arm64-py3.12/fn-abc123.zip"): body})
    result = harness.check_artifact_identity(lam, s3, "fn", "arm64", "3.12", "abc123", bucket="bkt",
                                             artifact_basename="fn")
    assert result.state == harness.PASS
    assert result.substitute is None


# ---------------------------------------------------------------------------
# ENC-TSK-P06 -- point 1 built its S3 key from the DEPLOYED function name, but
# _build.yml names artifacts after the SOURCE DIRECTORY. The key was wrong for
# essentially every function, so point 1 could never have passed with or
# without the s3:GetObject grant -- and nobody could see it, because it returned
# permission_denied and never reached the comparison. The check's own defect was
# hidden by the check being unable to run.
# ---------------------------------------------------------------------------

def test_artifact_basename_is_the_source_dir_not_the_deployed_name():
    """A heuristic would be wrong, which is why this reads the real map."""
    assert harness.resolve_artifact_basename("auth-refresh-gamma") == "auth_refresh"
    # the case that kills punctuation-swapping: a heuristic yields
    # devops_governance_mart, which does not exist.
    assert harness.resolve_artifact_basename("devops-governance-mart-gamma") == "governance_mart"
    # comma fan-out: one source dir, several deployed functions
    assert harness.resolve_artifact_basename(
        "enceladus-checkout-service-auto-gamma") == "checkout_service"


def test_unmapped_function_is_unknown_never_a_missing_artifact_fail():
    """An unresolvable name is something we could not check. Reporting it as
    artifact_missing would be a fabricated FAIL -- the mirror image of the
    fabricated PASS this harness exists to prevent."""
    assert harness.resolve_artifact_basename("no-such-function-anywhere") is None
    lam = FakeLambdaClient(config={"Architectures": ["arm64"], "CodeSha256": "x"})
    result = harness.check_artifact_identity(
        lam, FakeS3Client(), "no-such-function-anywhere", "arm64", "3.12", "abc123")
    assert result.state == harness.UNKNOWN
    assert result.reason_code == "artifact_name_unresolved"


def test_artifact_key_uses_the_basename_it_is_given():
    key = harness._artifact_key("auth_refresh", "arm64", "3.12", "deadbeef")
    assert key == "lambda-artifacts/arm64-py3.12/auth_refresh-deadbeef.zip"


# ===========================================================================
# ENC-TSK-P08 / ENC-ISS-665 -- point 4 repair
#
# The defect: point 4 read a CloudWatch log stream mid-flight, before an
# ERROR/Traceback had been written, and measured "freshness" against point
# 3's OWN invocation from seconds earlier in the same run -- manufacturing
# the freshness it then accepted. Four remedies, each proven below:
#   1. run-start freshness anchoring
#   2. terminated-invocation requirement (bounded poll, UNKNOWN on timeout)
#   3. cross-point contradiction assertion (load-bearing)
#   4. log-group-wide evaluation
# ===========================================================================

def _start_line(rid: str) -> dict:
    return {"message": f"START RequestId: {rid} Version: $LATEST"}


def _report_line(rid: str, ts: float) -> dict:
    return {"timestamp": ts, "message": f"REPORT RequestId: {rid} Duration: 12.3 ms"}


def _error_line(rid: str, ts: float) -> dict:
    return {"timestamp": ts, "message": f"[ERROR] RequestId: {rid} Traceback (most recent call last): boom"}


# ---------------------------------------------------------------------------
# Remedy 1 -- run-start freshness anchoring
# ---------------------------------------------------------------------------

def test_remedy1_evaluate_window_excludes_events_at_or_after_run_start():
    """A clean, terminated invocation that happens AT OR AFTER run_start_ms
    (i.e. caused by this harness run itself, such as point 3's own invoke)
    must never count as evidence of freshness -- it must be filtered out
    before it can influence the verdict, even if the caller's own query
    bounds regressed and over-fetched it."""
    run_start_ms = 1_700_000_000_000.0
    rid = "cccc3333-0000-0000-0000-000000000000"
    events = [
        {"timestamp": run_start_ms + 100, "message": f"START RequestId: {rid} Version: $LATEST"},
        {"timestamp": run_start_ms + 150, "message": f"REPORT RequestId: {rid} Duration: 10 ms"},
    ]
    state, signal, detail = harness._evaluate_schedule_window(
        events, now_ms=run_start_ms + 200, run_start_ms=run_start_ms, max_age_hours=26.0)
    assert state == harness.UNKNOWN
    assert signal == "no_activity"
    assert state != harness.PASS


def test_remedy1_duplication_path_schedule_disabled_point3_enabled_no_fresh_activity():
    """ENC-ISS-665's exact duplication path (AC-3): the schedule is disabled
    (no genuine historical firing), but point 3 is enabled and just invoked
    the function, producing a clean, terminated log entry SECONDS after this
    harness run started. Point 4 must NOT report this as fresh activity.
    """
    run_start_ms = 1_700_000_000_000.0
    point3_invoke_ts = run_start_ms + 5_000  # 5s after run start -- point 3's own invoke
    rid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    fresh_events = [
        {"timestamp": point3_invoke_ts, "message": f"START RequestId: {rid} Version: $LATEST"},
        {"timestamp": point3_invoke_ts + 50, "message": f"REPORT RequestId: {rid} Duration: 40 ms"},
    ]
    logs = FakeCloudWatchLogs(events=fresh_events, has_ever_run=True)

    state, detail = harness._probe_governance_mart_schedule(
        "devops-governance-mart-gamma", {"logs": logs, "run_start_ms": run_start_ms}, poll_attempts=1)
    assert state != harness.PASS, (
        f"point 4 must not report fresh activity from schedule-disabled + point-3-enabled "
        f"(ENC-ISS-665 duplication path), got state={state!r} detail={detail!r}")
    assert "clean" not in detail
    assert ("no activity" in detail.lower()) or ("schedule window" in detail.lower())

    # CONTRAST -- proves the anchor is what matters, not some other
    # accidental fix: the SAME event, evaluated as though "now" were the
    # anchor instead of the real run-start, DOES read as fresh/clean. This is
    # the exact pre-fix defect shape being reproduced deliberately.
    unanchored_state, _, _ = harness._evaluate_schedule_window(
        fresh_events, now_ms=point3_invoke_ts + 1000, run_start_ms=point3_invoke_ts + 1000,
        max_age_hours=26.0)
    assert unanchored_state == harness.PASS, (
        "sanity check: without run-start anchoring, point 3's own fresh invocation DOES look "
        "like a clean pass -- this is precisely the defect remedy 1 exists to close"
    )


# ---------------------------------------------------------------------------
# Remedy 2 -- terminated-invocation requirement
# ---------------------------------------------------------------------------

def test_remedy2_unterminated_invocation_is_unknown_not_pass():
    run_start_ms = 1_700_000_000_000.0
    rid = "d0d0d0d0-1111-2222-3333-444444444444"
    events = [{"timestamp": run_start_ms - 1000, "message": f"START RequestId: {rid} Version: $LATEST"}]
    state, signal, detail = harness._evaluate_schedule_window(
        events, now_ms=run_start_ms, run_start_ms=run_start_ms, max_age_hours=26.0)
    assert state == harness.UNKNOWN
    assert signal == "not_terminated"
    assert "reading a stream before" in detail


def test_remedy2_bounded_poll_never_escalates_unterminated_to_pass():
    run_start_ms = 1_700_000_000_000.0
    rid = "11111111-2222-3333-4444-555555555555"
    not_terminated = [{"timestamp": run_start_ms - 1000, "message": f"START RequestId: {rid} Version: $LATEST"}]
    logs = FakeCloudWatchLogs(sequence=[not_terminated, not_terminated, not_terminated])
    sleeps = []
    state, detail = harness._probe_governance_mart_schedule(
        "devops-governance-mart-gamma", {"logs": logs, "run_start_ms": run_start_ms},
        poll_attempts=3, poll_interval_s=0.01, sleep=sleeps.append)
    assert state == harness.UNKNOWN, "an invocation that never terminates must NEVER be promoted to pass"
    assert "gave up after 3 attempt" in detail
    assert len(sleeps) == 2, "must sleep between attempts, never after the final one"


def test_remedy2_bounded_poll_succeeds_once_termination_appears():
    # This path reaches the freshness/staleness check, which the probe
    # computes against the REAL clock (time.time()) -- unlike the other
    # remedy-2 tests, which resolve before ever reaching that comparison.
    # So run_start_ms must be real-clock-relative, not an arbitrary fixed
    # past epoch (which would always read as > max_age_hours stale).
    run_start_ms = time.time() * 1000.0 - 2_000  # "harness run started 2s ago"
    rid = "aaaaaaaa-1111-2222-3333-444444444444"
    not_terminated = [{"timestamp": run_start_ms - 1000, "message": f"START RequestId: {rid} Version: $LATEST"}]
    terminated_clean = not_terminated + [
        {"timestamp": run_start_ms - 900, "message": f"REPORT RequestId: {rid} Duration: 12 ms"}]
    logs = FakeCloudWatchLogs(sequence=[not_terminated, terminated_clean])
    sleeps = []
    state, detail = harness._probe_governance_mart_schedule(
        "devops-governance-mart-gamma", {"logs": logs, "run_start_ms": run_start_ms},
        poll_attempts=3, poll_interval_s=0.01, sleep=sleeps.append)
    assert state == harness.PASS
    assert len(sleeps) == 1


# ---------------------------------------------------------------------------
# Remedy 4 -- log-group-wide evaluation
# ---------------------------------------------------------------------------

def test_remedy4_log_group_wide_catches_error_masked_by_a_newer_clean_invocation():
    """A naive 'just look at the single newest stream' check would see only
    the clean, newer invocation (a concurrent execution environment) and miss
    the erroring, slightly-older one entirely -- log-group-wide evaluation
    must not."""
    run_start_ms = 1_700_000_000_000.0
    older_erroring_rid = "aaaa1111-0000-0000-0000-000000000000"
    newer_clean_rid = "bbbb2222-0000-0000-0000-000000000000"
    events = [
        {"timestamp": run_start_ms - 5000, "message": f"START RequestId: {older_erroring_rid} Version: $LATEST"},
        {"timestamp": run_start_ms - 4950,
         "message": f"[ERROR] RequestId: {older_erroring_rid} Traceback (most recent call last): NoSuchBucket"},
        {"timestamp": run_start_ms - 4900, "message": f"REPORT RequestId: {older_erroring_rid} Duration: 100 ms"},
        {"timestamp": run_start_ms - 1000, "message": f"START RequestId: {newer_clean_rid} Version: $LATEST"},
        {"timestamp": run_start_ms - 950, "message": f"REPORT RequestId: {newer_clean_rid} Duration: 40 ms"},
    ]
    state, signal, detail = harness._evaluate_schedule_window(
        events, now_ms=run_start_ms, run_start_ms=run_start_ms, max_age_hours=26.0)
    assert state == harness.FAIL, (
        "a single-newest-stream check would see only the clean newer invocation and miss the "
        "erroring one -- log-group-wide evaluation must catch it regardless"
    )
    assert signal == "error_found"
    assert older_erroring_rid in detail


# ---------------------------------------------------------------------------
# Remedy 3 -- cross-point contradiction assertion (LOAD-BEARING)
#
# AC-2's negative control: a synthetic run where point 3 FAILS must make
# point 4 structurally unable to PASS. Proven three ways: the guard function
# directly, through check_integration_edge with a probe that is deliberately
# naive (bypassing remedies 1/2/4 entirely, simulating the pre-fix probe), and
# through a full evaluate_function run.
# ---------------------------------------------------------------------------

def test_remedy3_enforce_no_pass_when_point3_failed_direct():
    point3 = harness.PointResult(3, "live_invocation", harness.FAIL, "NoSuchBucket", reason_code="function_error")
    naive_point4 = harness.PointResult(4, "integration_edge", harness.PASS, "looked clean", reason_code="probe_result")
    result = harness._enforce_no_pass_when_point3_failed(naive_point4, point3)
    assert result.state == harness.FAIL
    assert result.reason_code == "point3_point4_contradiction"


def test_remedy3_no_override_when_point3_did_not_fail():
    for point3_state in (harness.PASS, harness.UNKNOWN):
        point3 = harness.PointResult(3, "live_invocation", point3_state, "", reason_code="unspecified")
        point4 = harness.PointResult(4, "integration_edge", harness.PASS, "looked clean", reason_code="probe_result")
        result = harness._enforce_no_pass_when_point3_failed(point4, point3)
        assert result is point4, "must be a no-op whenever point 3 did not fail"


def test_remedy3_holds_even_with_a_naive_always_pass_probe():
    """AC-2, negative control: proven with a deliberately naive probe that
    ALWAYS returns PASS, completely bypassing remedies 1/2/4. If remedy 3 is
    truly independent of the freshness/anchoring machinery, it must still
    catch this."""
    harness.PROBE_REGISTRY["_test_naive_always_pass"] = lambda fn, clients: (harness.PASS, "always looks clean")
    try:
        point3_fail = harness.PointResult(3, "live_invocation", harness.FAIL, "FunctionError: NoSuchBucket",
                                           reason_code="function_error")
        result = harness.check_integration_edge("_test_naive_always_pass", {}, point3_result=point3_fail)
        assert result.state != harness.PASS, "point 4 must be structurally unable to pass when point 3 failed"
        assert result.state == harness.FAIL
        assert result.reason_code == "point3_point4_contradiction"
    finally:
        del harness.PROBE_REGISTRY["_test_naive_always_pass"]


def test_remedy3_full_evaluate_function_run_point3_fails_point4_cannot_pass():
    """The full synthetic run, AC-2's literal ask: evaluate_function end to
    end with point 3 FAILING (a real FunctionError, modeled on the live
    ENC-ISS-666 devops-governance-mart-gamma NoSuchBucket failure) and a
    naive always-PASS probe registered, proving the WIRING -- not just the
    helper function in isolation -- forbids the contradiction.
    """
    fn_name = "_test_full_run_contradiction_fn"
    harness.PROBE_REGISTRY[fn_name] = lambda fn, clients: (harness.PASS, "naive: always clean")
    try:
        lam = FakeLambdaClient(
            config={"Architectures": ["arm64"], "Layers": [], "CodeSha256": "x"},
            invoke_response={"StatusCode": 200, "FunctionError": "Unhandled",
                              "Payload": FakeBody(b'{"errorType": "NoSuchBucket"}')},
        )
        report = harness.evaluate_function(
            lambda_client=lam, s3_client=FakeS3Client(), logs_client=object(),
            function_name=fn_name, commit_sha=None,
            negative_control_test="tools/does_not_exist_xyz.py",  # keeps point 5 deterministic, offline
        )
        point3 = next(p for p in report.points if p.point == 3)
        point4 = next(p for p in report.points if p.point == 4)
        assert point3.state == harness.FAIL
        assert point4.state != harness.PASS, "structurally impossible: point 4 cannot pass when point 3 failed"
        assert point4.reason_code == "point3_point4_contradiction"
        assert report.overall == harness.FAIL
    finally:
        del harness.PROBE_REGISTRY[fn_name]


# ===========================================================================
# ENC-TSK-P09 / ENC-ISS-668 -- external-dependency register and the ATTESTED
# rollup verdict.
#
# 33 of 51 gamma functions attach AWS-AppConfig-Extension-Arm64:147, owned by
# a different AWS account. Point 2 correctly cannot GetLayerVersion
# cross-account -- but that UNKNOWN used to sink FunctionReport.overall to a
# permanent, undifferentiated "unknown" with no way to ever reach any other
# verdict. These tests prove: (1) the register classifies known external
# dependencies distinctly from a generic layer_not_found mystery, (2) the
# rollup reaches an explicit ATTESTED verdict naming the unverified points
# when that is the ONLY kind of non-pass present, (3) an unqualified PASS
# stays structurally impossible whenever any point is UNKNOWN, and (4) the
# 33 affected functions reach a determinate verdict.
# ===========================================================================

def test_p09_appconfig_extension_layer_resolves_to_external_dependency_declared():
    lam = FakeLambdaClient(
        config={"Architectures": ["arm64"],
                "Layers": [{"Arn": "arn:aws:lambda:us-west-2:359756378197:layer:AWS-AppConfig-Extension-Arm64:147"}]},
        layer_error=Exception("ResourceNotFoundException: Layer version does not exist"),
    )
    result = harness.check_layer_coherence(lam, "auth-refresh-gamma", downloader=lambda url: b"",
                                            classify_so=lambda p: None)
    assert result.state == harness.UNKNOWN
    # ENC-TSK-P18 TIGHTENED THIS, and the tightening is the point. ENC-TSK-P09
    # classified this by layer NAME as external_dependency_declared. P18 adds an
    # EXACT-ARN allowlist which is consulted first, so this specific reviewed ARN
    # now carries the more specific external_dependency_cross_account_allowlisted.
    # P09's actual guarantee is unchanged and re-asserted below: distinct from a
    # generic layer_not_found, and still attestable.
    assert result.reason_code == "external_dependency_cross_account_allowlisted", (
        "must be classified distinctly from a generic layer_not_found mystery -- this is a "
        "documented, named, cross-account dependency (ENC-TSK-P09/ENC-ISS-668), now matched "
        "by exact ARN (ENC-TSK-P18)"
    )
    assert result.reason_code != "layer_not_found"
    assert result.reason_code in harness.ATTESTABLE_REASON_CODES
    assert "359756378197" in result.detail
    assert "arm64" in result.detail.lower()


def test_p09_devops_owned_layers_resolve_distinctly_from_layer_not_found():
    for layer_name, version in (("devops-json-to-parquet-pyarrow", 3), ("devops-json-to-parquet-numpy", 2)):
        lam = FakeLambdaClient(
            config={"Architectures": ["arm64"],
                    "Layers": [{"Arn": f"arn:aws:lambda:us-west-2:999999999999:layer:{layer_name}:{version}"}]},
            layer_error=Exception("ResourceNotFoundException: Layer version does not exist"),
        )
        result = harness.check_layer_coherence(lam, "some-fn", downloader=lambda url: b"", classify_so=lambda p: None)
        assert result.state == harness.UNKNOWN
        assert result.reason_code == "external_dependency_owned_devops", layer_name
        assert "NX-2021-L/devops" in result.detail
        assert result.reason_code != "layer_not_found"


def test_p09_unregistered_missing_layer_still_reports_plain_layer_not_found():
    """The register must not swallow genuine mysteries -- an unregistered
    layer that 404s stays exactly the undifferentiated layer_not_found it
    always was."""
    lam = FakeLambdaClient(
        config={"Architectures": ["arm64"],
                "Layers": [{"Arn": "arn:aws:lambda:us-west-2:1:layer:totally-unknown-layer:1"}]},
        layer_error=Exception("ResourceNotFoundException: Layer version does not exist"),
    )
    result = harness.check_layer_coherence(lam, "fn", downloader=lambda url: b"", classify_so=lambda p: None)
    assert result.reason_code == "layer_not_found"


def test_p09_function_report_reaches_attested_when_only_non_pass_is_external_dependency():
    points = [
        harness.PointResult(1, "artifact_identity", harness.PASS, "", reason_code="digest_match"),
        harness.PointResult(2, "layer_coherence", harness.UNKNOWN, "AWS-AppConfig-Extension-Arm64 cross-account",
                             reason_code="external_dependency_declared"),
        harness.PointResult(3, "live_invocation", harness.PASS, "", reason_code="invoked_ok"),
        harness.PointResult(4, "integration_edge", harness.PASS, "", reason_code="probe_result"),
        harness.PointResult(5, "ci_predicate_observed_failing", harness.PASS, "", reason_code="ci_history_confirmed_red"),
    ]
    report = harness.FunctionReport(function_name="auth-refresh-gamma", points=points)
    assert report.overall == harness.ATTESTED
    assert report.overall != harness.PASS
    assert report.attested_points == [2]
    assert report.attestation_note is not None
    assert "external_dependency_declared" in report.attestation_note
    d = report.to_dict()
    assert d["overall"] == "attested"
    assert d["overall"] != "pass"
    assert d["attested_points"] == [2]
    assert d["attestation_note"] is not None


def test_p09_attested_requires_every_non_pass_point_to_be_attestable():
    points = [
        harness.PointResult(1, "artifact_identity", harness.PASS, "", reason_code="digest_match"),
        harness.PointResult(2, "layer_coherence", harness.UNKNOWN, "", reason_code="external_dependency_declared"),
        harness.PointResult(3, "live_invocation", harness.PASS, "", reason_code="invoked_ok"),
        harness.PointResult(4, "integration_edge", harness.UNKNOWN, "", reason_code="no_probe_registered"),
        harness.PointResult(5, "ci_predicate_observed_failing", harness.PASS, "", reason_code="ci_history_confirmed_red"),
    ]
    report = harness.FunctionReport(function_name="fn", points=points)
    assert report.overall == harness.UNKNOWN, (
        "a coverage gap (no_probe_registered) is not a documented external-dependency ceiling -- "
        "mixing it in must NOT be laundered into an attested verdict"
    )
    assert report.attestation_note is None
    assert report.attested_points == []


def test_p09_fail_beats_attested():
    points = [
        harness.PointResult(1, "artifact_identity", harness.FAIL, "", reason_code="digest_mismatch"),
        harness.PointResult(2, "layer_coherence", harness.UNKNOWN, "", reason_code="external_dependency_declared"),
        harness.PointResult(3, "live_invocation", harness.PASS, "", reason_code="invoked_ok"),
        harness.PointResult(4, "integration_edge", harness.PASS, "", reason_code="probe_result"),
        harness.PointResult(5, "ci_predicate_observed_failing", harness.PASS, "", reason_code="ci_history_confirmed_red"),
    ]
    report = harness.FunctionReport(function_name="fn", points=points)
    assert report.overall == harness.FAIL


def test_p09_unqualified_pass_is_structurally_impossible_when_any_point_unknown():
    """Requirement 3: an unqualified overall PASS must stay structurally
    impossible when any point is UNKNOWN -- whether that unknown is
    attestable or not."""
    for reason_code in ("external_dependency_declared", "external_dependency_owned_devops",
                        "permission_denied", "no_probe_registered", "layer_not_found"):
        points = [
            harness.PointResult(1, "p1", harness.PASS, "", reason_code="digest_match"),
            harness.PointResult(2, "p2", harness.UNKNOWN, "", reason_code=reason_code),
            harness.PointResult(3, "p3", harness.PASS, "", reason_code="invoked_ok"),
            harness.PointResult(4, "p4", harness.PASS, "", reason_code="probe_result"),
            harness.PointResult(5, "p5", harness.PASS, "", reason_code="ci_history_confirmed_red"),
        ]
        report = harness.FunctionReport(function_name="fn", points=points)
        assert report.overall != harness.PASS, f"reason_code={reason_code} must never yield a bare pass"
        assert report.overall in (harness.ATTESTED, harness.UNKNOWN)


def test_p09_all_33_appconfig_functions_reach_a_determinate_verdict():
    """ENC-ISS-668: 33 of 51 gamma functions attach AWS-AppConfig-Extension-
    Arm64:147. Before this fix every one of them was stuck at plain 'unknown'
    forever, indistinguishable from an undiagnosed gap. Prove all 33 reach an
    explicit, named ATTESTED verdict -- never a bare pass, never stuck.
    """
    thirty_three_function_names = [f"gamma-fn-{i:02d}" for i in range(33)]
    reports = []
    for fn_name in thirty_three_function_names:
        lam = FakeLambdaClient(
            config={"Architectures": ["arm64"],
                    "Layers": [{"Arn": "arn:aws:lambda:us-west-2:359756378197:layer:AWS-AppConfig-Extension-Arm64:147"}],
                    "CodeSha256": "deadbeef"},
            layer_error=Exception("ResourceNotFoundException: Layer version does not exist"),
        )
        point1 = harness.PointResult(1, "artifact_identity", harness.PASS, "", reason_code="digest_match")
        point2 = harness.check_layer_coherence(lam, fn_name, downloader=lambda url: b"", classify_so=lambda p: None)
        point3 = harness.PointResult(3, "live_invocation", harness.PASS, "", reason_code="invoked_ok")
        point4 = harness.PointResult(4, "integration_edge", harness.PASS, "", reason_code="probe_result")
        point5 = harness.PointResult(5, "ci_predicate_observed_failing", harness.PASS, "",
                                      reason_code="ci_history_confirmed_red")
        reports.append(harness.FunctionReport(function_name=fn_name,
                                               points=[point1, point2, point3, point4, point5]))

    assert len(reports) == 33
    non_determinate = [r.function_name for r in reports if r.overall == harness.UNKNOWN]
    assert non_determinate == [], f"still stuck at plain unknown, never reaching a verdict: {non_determinate}"
    assert all(r.overall == harness.ATTESTED for r in reports)
    assert all(r.overall != harness.PASS for r in reports), "attested is not a fabricated pass"
    assert all(2 in r.attested_points for r in reports)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))


# ---------------------------------------------------------------------------
# ENC-TSK-P18 / ENC-ISS-668 -- exact-match cross-account layer ARN allowlist.
#
# THE GOVERNING DISTINCTION, because it decides whether this whole change is
# legitimate: ENC-TSK-O96's rename was legitimate because the check GENUINELY
# COULD NOT SEE -- lambda:GetLayerVersion cannot read another account's layer
# version, full stop, and renaming that outcome describes a limit of the
# vantage point. An ENC-ISS-665-style rename would be illegitimate because
# there the check SAW WRONGLY -- it looked at real evidence and drew a false
# conclusion, and renaming that sanctions a lie. This task applies the pattern
# only in the first shape.
#
# An allowlist is a WIDENING, and a widening without a negative control is how
# the next vacuous pass gets built. Hence
# test_p18_negative_control_* below: it is not decoration.
# ---------------------------------------------------------------------------

APPCONFIG_ARN = "arn:aws:lambda:us-west-2:359756378197:layer:AWS-AppConfig-Extension-Arm64:147"
SELF_ACCOUNT = "111122223333"
FUNCTION_ARN = f"arn:aws:lambda:us-west-2:{SELF_ACCOUNT}:function:some-fn-gamma"
# Deliberately unrelated: a DIFFERENT vendor, a DIFFERENT account, appearing
# in no governed declaration anywhere in this repo.
UNDECLARED_CROSS_ACCOUNT_ARN = (
    "arn:aws:lambda:us-west-2:999988887777:layer:Totally-Unrelated-Vendor-Layer:1")


def _layer_fn_config(layer_arn):
    return {"Architectures": ["arm64"],
            "FunctionArn": FUNCTION_ARN,
            "Layers": [{"Arn": layer_arn}]}


def _cross_account_client(layer_arn):
    return FakeLambdaClient(
        config=_layer_fn_config(layer_arn),
        layer_error=Exception("ResourceNotFoundException: Layer version does not exist"),
    )


def test_p18_allowlist_records_appconfig_147_arch_as_a_declared_fact():
    """AC-1: the exact ARN is recorded, with its architecture, as a declared fact."""
    allowlist = harness.load_external_layer_arn_allowlist(use_cache=False)
    assert APPCONFIG_ARN in allowlist, (
        "the cross-account AppConfig extension 33 of 51 functions attach must be declared")
    entry = allowlist[APPCONFIG_ARN]
    assert entry["declared_arch"] == "arm64"
    assert entry["owner_account"] == "359756378197"
    # Sourced from the governed closure, not a second hand-typed table that can drift.
    assert entry["source"] == "infrastructure/component_dependency_closure.json"


@pytest.mark.parametrize("near_miss", [
    # A version-number prefix relationship: :147 must not admit :1470.
    "arn:aws:lambda:us-west-2:359756378197:layer:AWS-AppConfig-Extension-Arm64:1470",
    # The same layer, a DIFFERENT version nobody reviewed.
    "arn:aws:lambda:us-west-2:359756378197:layer:AWS-AppConfig-Extension-Arm64:148",
    # The family without a version -- a prefix expressed as an ARN.
    "arn:aws:lambda:us-west-2:359756378197:layer:AWS-AppConfig-Extension-Arm64",
    # An explicit wildcard.
    "arn:aws:lambda:us-west-2:359756378197:layer:AWS-AppConfig-Extension-Arm64:*",
    # Same name and version, DIFFERENT account.
    "arn:aws:lambda:us-west-2:999988887777:layer:AWS-AppConfig-Extension-Arm64:147",
    # Same ARN, different region.
    "arn:aws:lambda:us-east-1:359756378197:layer:AWS-AppConfig-Extension-Arm64:147",
    # Whitespace and case are NOT normalized away.
    APPCONFIG_ARN + " ",
    APPCONFIG_ARN.upper(),
])
def test_p18_allowlist_lookup_is_exact_match_never_prefix_or_wildcard(near_miss):
    """AC-1: exact match only. Every one of these is a string the allowlist
    does not contain, and 'close to a declared ARN' is not 'declared'."""
    assert harness.lookup_allowlisted_layer_arn(near_miss) is None, near_miss
    # ...while the exact string still resolves.
    assert harness.lookup_allowlisted_layer_arn(APPCONFIG_ARN) is not None


def test_p18_declared_cross_account_layer_is_distinct_from_layer_not_found():
    """AC-0: a cross-account ceiling reads as a ceiling, not a missing layer."""
    result = harness.check_layer_coherence(
        _cross_account_client(APPCONFIG_ARN), "some-fn-gamma",
        downloader=lambda url: b"", classify_so=lambda p: None)
    assert result.state == harness.UNKNOWN
    assert result.reason_code == "external_dependency_cross_account_allowlisted"
    assert result.reason_code != "layer_not_found"
    assert "359756378197" in result.detail


def test_p18_negative_control_undeclared_cross_account_layer_does_not_inherit_exemption():
    """AC-4, THE NEGATIVE CONTROL. A synthetic cross-account layer ARN that is
    NOT on the allowlist must still return unknown and must NOT inherit the
    exemption. If this test ever passes trivially -- if the reason code it
    produces is ever added to ATTESTABLE_REASON_CODES -- the allowlist has
    stopped being an allowlist and every cross-account layer is exempt."""
    result = harness.check_layer_coherence(
        _cross_account_client(UNDECLARED_CROSS_ACCOUNT_ARN), "some-fn-gamma",
        downloader=lambda url: b"", classify_so=lambda p: None)

    assert result.state == harness.UNKNOWN, "still unknown -- never a pass"
    assert result.reason_code == "cross_account_layer_unverifiable"
    # It is legible as a cross-account ceiling (AC-0 applies here too)...
    assert "999988887777" in result.detail
    # ...but it is NOT attestable, and that is the entire control.
    assert result.reason_code not in harness.ATTESTABLE_REASON_CODES

    # And the consequence at the rollup: the function does NOT reach ATTESTED.
    report = harness.FunctionReport(
        function_name="some-fn-gamma",
        points=[
            harness.PointResult(1, "artifact_identity", harness.PASS, "", reason_code="digest_match"),
            result,
            harness.PointResult(3, "live_invocation", harness.PASS, "", reason_code="invoked_ok"),
            harness.PointResult(4, "integration_edge", harness.PASS, "", reason_code="probe_result"),
            harness.PointResult(5, "ci_predicate_observed_failing", harness.PASS, "",
                                 reason_code="ci_history_confirmed_red"),
        ])
    assert report.overall == harness.UNKNOWN, (
        "an UNDECLARED cross-account ceiling must sink the verdict to plain unknown -- "
        "reaching ATTESTED here would mean the allowlist admitted a layer nobody reviewed")
    assert report.overall != harness.ATTESTED
    assert report.overall != harness.PASS
    assert report.attested_points == []


def test_p18_cross_account_unverifiable_is_permanently_non_attestable():
    """A structural guard on the guard: the negative control above is only
    meaningful while this code stays OUT of the attestable set. Asserting it
    directly means a future widening trips a named test rather than quietly
    converting the control into a tautology."""
    assert "cross_account_layer_unverifiable" not in harness.ATTESTABLE_REASON_CODES
    assert "external_dependency_cross_account_allowlisted" in harness.ATTESTABLE_REASON_CODES


def test_p18_declared_ceiling_reaches_attested_naming_the_unverified_point():
    """AC-2: a function whose only non-pass point is a DECLARED cross-account
    ceiling reaches a determinate ATTESTED verdict that NAMES the point."""
    report = harness.FunctionReport(
        function_name="auth-refresh-gamma",
        points=[
            harness.PointResult(1, "artifact_identity", harness.PASS, "", reason_code="digest_match"),
            harness.PointResult(2, "layer_coherence", harness.UNKNOWN, APPCONFIG_ARN,
                                 reason_code="external_dependency_cross_account_allowlisted"),
            harness.PointResult(3, "live_invocation", harness.PASS, "", reason_code="invoked_ok"),
            harness.PointResult(4, "integration_edge", harness.PASS, "", reason_code="probe_result"),
            harness.PointResult(5, "ci_predicate_observed_failing", harness.PASS, "",
                                 reason_code="ci_history_confirmed_red"),
        ])
    assert report.overall == harness.ATTESTED
    assert report.overall != harness.PASS, "attested is a determinate verdict, not a pass"
    assert report.attested_points == [2]
    assert "point 2 (layer_coherence)" in report.attestation_note


def test_p18_unqualified_pass_is_structurally_impossible_with_any_unknown():
    """AC-2's second half, asserted over the whole reason-code vocabulary: no
    reason_code, attestable or not, can produce an unqualified PASS while any
    point is UNKNOWN."""
    for reason_code in sorted(harness.REASON_CODES):
        report = harness.FunctionReport(
            function_name="fn",
            points=[
                harness.PointResult(1, "artifact_identity", harness.PASS, "",
                                     reason_code="digest_match"),
                harness.PointResult(2, "layer_coherence", harness.UNKNOWN, "",
                                     reason_code=reason_code),
            ])
        assert report.overall != harness.PASS, reason_code
        assert report.overall in (harness.ATTESTED, harness.UNKNOWN), reason_code


def test_p18_all_affected_functions_reach_a_determinate_verdict():
    """AC-3: all 33 functions blocked by this one layer reach a determinate
    verdict, where previously every one of them was stuck at plain unknown."""
    reports = []
    for i in range(33):
        name = f"affected-fn-{i}-gamma"
        point2 = harness.check_layer_coherence(
            _cross_account_client(APPCONFIG_ARN), name,
            downloader=lambda url: b"", classify_so=lambda p: None)
        reports.append(harness.FunctionReport(
            function_name=name,
            points=[
                harness.PointResult(1, "artifact_identity", harness.PASS, "",
                                     reason_code="digest_match"),
                point2,
                harness.PointResult(3, "live_invocation", harness.PASS, "",
                                     reason_code="invoked_ok"),
                harness.PointResult(4, "integration_edge", harness.PASS, "",
                                     reason_code="probe_result"),
                harness.PointResult(5, "ci_predicate_observed_failing", harness.PASS, "",
                                     reason_code="ci_history_confirmed_red"),
            ]))
    assert len(reports) == 33
    assert all(r.overall == harness.ATTESTED for r in reports)
    assert all(r.overall != harness.PASS for r in reports), "determinate, not fabricated"
    assert all(2 in r.attested_points for r in reports)
    assert all(r.attestation_note and "point 2" in r.attestation_note for r in reports)


def test_p18_allowlist_fails_closed_when_the_closure_cannot_be_read(tmp_path):
    """An unreadable declaration must NARROW what is exempt, never widen it."""
    missing = tmp_path / "does_not_exist.json"
    assert harness.load_external_layer_arn_allowlist(missing, use_cache=False) == {}

    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{not json", encoding="utf-8")
    assert harness.load_external_layer_arn_allowlist(corrupt, use_cache=False) == {}


def test_p18_same_account_layer_failure_is_not_called_cross_account():
    """The cross-account code must mean what it says: a layer in the SAME
    account that fails to resolve is still a layer_not_found mystery."""
    same_account_arn = f"arn:aws:lambda:us-west-2:{SELF_ACCOUNT}:layer:some-own-layer:4"
    result = harness.check_layer_coherence(
        _cross_account_client(same_account_arn), "some-fn-gamma",
        downloader=lambda url: b"", classify_so=lambda p: None)
    assert result.state == harness.UNKNOWN
    assert result.reason_code == "layer_not_found"
    assert result.reason_code not in harness.ATTESTABLE_REASON_CODES


# ---------------------------------------------------------------------------
# ENC-TSK-P19 / ENC-ISS-665 -- point-4 probe coverage and declared ownership.
#
# ENC-TSK-P08 DID NOT ADD PROBES. Re-reading its diff before writing these:
# it fixed the self-fulfilling freshness signal (run-start anchoring), the
# mid-flight log read (terminated-invocation requirement, log-group-wide
# evaluation), and added the point3/point4 contradiction assertion. Coverage
# was 2 of 51 before it and 2 of 51 after it.
# ---------------------------------------------------------------------------

class FakeApiGatewayV2Client:
    """Fake apigatewayv2. ENC-TSK-P20: models REAL PAGINATION.

    page_size simulates the service's bounded first page. The live gamma API
    returns 25 of 184 routes unpaginated, which is what made the escalation
    probe report a FALSE FAIL on a /deny route that exists. A fake that always
    returns everything in one page cannot reproduce that class of defect, so it
    would have let the bug ship twice.
    """

    def __init__(self, *, apis=None, routes=None, authorizers=None,
                 apis_error=None, authorizer_error=None, page_size=None):
        self._apis = apis or []
        self._routes = routes or {}
        self._authorizers = authorizers or {}
        self._apis_error = apis_error
        self._authorizer_error = authorizer_error
        self._page_size = page_size

    def _page(self, items, NextToken=None, **_kwargs):  # noqa: N803
        if not self._page_size:
            return {"Items": items}
        start = int(NextToken) if NextToken else 0
        chunk = items[start:start + self._page_size]
        out = {"Items": chunk}
        nxt = start + self._page_size
        if nxt < len(items):
            out["NextToken"] = str(nxt)
        return out

    def get_apis(self, **kwargs):
        if self._apis_error:
            raise self._apis_error
        return self._page(self._apis, **kwargs)

    def get_routes(self, ApiId, **kwargs):  # noqa: N803
        return self._page(self._routes.get(ApiId, []), **kwargs)

    def get_authorizer(self, ApiId, AuthorizerId):  # noqa: N803
        if self._authorizer_error:
            raise self._authorizer_error
        return self._authorizers[AuthorizerId]


ESC_FN = "escalation-decision-authorizer-gamma"
ESC_BASE = "POST /api/v1/coordination/escalations/{projectId}/{escalationId}"


def _escalation_api(approve_auth, deny_auth):
    routes = []
    if approve_auth is not None:
        routes.append({"RouteKey": f"{ESC_BASE}/approve", "AuthorizerId": approve_auth})
    else:
        routes.append({"RouteKey": f"{ESC_BASE}/approve"})
    if deny_auth is not None:
        routes.append({"RouteKey": f"{ESC_BASE}/deny", "AuthorizerId": deny_auth})
    else:
        routes.append({"RouteKey": f"{ESC_BASE}/deny"})
    return FakeApiGatewayV2Client(
        apis=[{"ApiId": "api1"}],
        routes={"api1": routes},
        authorizers={
            "auth-esc": {"Name": "escalation", "AuthorizerUri": f"arn:.../{ESC_FN}/invocations"},
            "auth-other": {"Name": "cognito", "AuthorizerUri": "arn:.../some-other-fn/invocations"},
        })


def test_p19_escalation_authorizer_probe_is_registered_for_both_planes():
    """AC-0: coverage extended beyond 2 of 51 -- the edges O90 AC-1 names."""
    assert "escalation-decision-authorizer" in harness.PROBE_REGISTRY
    assert "escalation-decision-authorizer-gamma" in harness.PROBE_REGISTRY


def test_p19_escalation_probe_passes_only_when_both_routes_are_guarded():
    state, detail = harness._probe_escalation_authorizer_routes(
        ESC_FN, {"apigatewayv2": _escalation_api("auth-esc", "auth-esc")})
    assert state == harness.PASS
    assert "/approve" in detail and "/deny" in detail


def test_p19_escalation_probe_fails_when_only_the_approve_route_is_guarded():
    """The asymmetry that matters: an authorizer on approve but not deny is a
    live authorization hole, and every function-level point reports the Lambda
    as perfectly healthy while it exists."""
    state, detail = harness._probe_escalation_authorizer_routes(
        ESC_FN, {"apigatewayv2": _escalation_api("auth-esc", None)})
    assert state == harness.FAIL
    assert "/deny" in detail


def test_p19_escalation_probe_fails_when_deny_route_uses_a_different_authorizer():
    state, detail = harness._probe_escalation_authorizer_routes(
        ESC_FN, {"apigatewayv2": _escalation_api("auth-esc", "auth-other")})
    assert state == harness.FAIL
    assert "deny" in detail


def test_p19_escalation_probe_is_unknown_not_pass_without_a_client():
    state, _ = harness._probe_escalation_authorizer_routes(ESC_FN, {})
    assert state == harness.UNKNOWN


def test_p19_escalation_probe_is_unknown_not_pass_when_apis_cannot_be_listed():
    state, _ = harness._probe_escalation_authorizer_routes(
        ESC_FN, {"apigatewayv2": FakeApiGatewayV2Client(
            apis_error=Exception("AccessDeniedException"))})
    assert state == harness.UNKNOWN


class FakeS3ListClient:
    def __init__(self, *, contents=None, error=None):
        self._contents = contents
        self._error = error

    def list_objects_v2(self, Bucket, Prefix):  # noqa: N803
        if self._error:
            raise self._error
        return {"Contents": self._contents or []}


def _mart_obj(key, age_hours, now_ms):
    ts = (now_ms - age_hours * 3_600_000.0) / 1000.0
    from datetime import datetime as _dt, timezone as _tz
    return {"Key": key, "LastModified": _dt.fromtimestamp(ts, tz=_tz.utc)}


def test_p19_mart_production_probe_fails_when_no_mart_was_produced():
    """AC-0: 'the mart must PRODUCE a mart' -- the half schedule freshness
    cannot see. A run can fire on time, exit cleanly and write nothing."""
    state, detail = harness._probe_governance_mart_produced(
        "devops-governance-mart-gamma",
        {"s3": FakeS3ListClient(contents=[]), "run_start_ms": time.time() * 1000.0})
    assert state == harness.FAIL
    assert "produced no mart" in detail


def test_p19_mart_production_probe_fails_on_a_stale_mart():
    now_ms = time.time() * 1000.0
    state, detail = harness._probe_governance_mart_produced(
        "devops-governance-mart-gamma",
        {"s3": FakeS3ListClient(contents=[
            _mart_obj("warehouse/devops/tasks/data.parquet", 400.0, now_ms)]),
         "run_start_ms": now_ms})
    assert state == harness.FAIL
    assert "stale" in detail


def test_p19_mart_production_probe_passes_on_a_fresh_mart():
    now_ms = time.time() * 1000.0
    state, _ = harness._probe_governance_mart_produced(
        "devops-governance-mart-gamma",
        {"s3": FakeS3ListClient(contents=[
            _mart_obj("warehouse/devops/tasks/data.parquet", 2.0, now_ms)]),
         "run_start_ms": now_ms})
    assert state == harness.PASS


def test_p19_mart_production_probe_is_unknown_not_pass_when_listing_is_denied():
    state, detail = harness._probe_governance_mart_produced(
        "devops-governance-mart-gamma",
        {"s3": FakeS3ListClient(error=Exception("AccessDenied")),
         "run_start_ms": time.time() * 1000.0})
    assert state == harness.UNKNOWN
    assert "permission ceiling" in detail


def test_p19_mart_composite_fails_when_schedule_is_clean_but_no_mart_was_produced(monkeypatch):
    """The combination is worst-wins. A clean schedule must not cover for an
    absent mart -- combining these either-passes would rebuild the vacuity
    point 4 exists to eliminate."""
    monkeypatch.setattr(harness, "_probe_governance_mart_schedule",
                        lambda fn, clients: (harness.PASS, "schedule clean"))
    state, detail = harness._probe_governance_mart(
        "devops-governance-mart-gamma",
        {"s3": FakeS3ListClient(contents=[]), "run_start_ms": time.time() * 1000.0})
    assert state == harness.FAIL
    assert "schedule clean" in detail and "produced no mart" in detail


def test_p19_mart_composite_still_fails_on_a_dead_schedule_with_fresh_output(monkeypatch):
    now_ms = time.time() * 1000.0
    monkeypatch.setattr(harness, "_probe_governance_mart_schedule",
                        lambda fn, clients: (harness.FAIL, "schedule stale"))
    state, _ = harness._probe_governance_mart(
        "devops-governance-mart-gamma",
        {"s3": FakeS3ListClient(contents=[
            _mart_obj("warehouse/devops/tasks/data.parquet", 1.0, now_ms)]),
         "run_start_ms": now_ms})
    assert state == harness.FAIL


def test_p19_unregistered_function_declares_no_probe_registered(monkeypatch):
    """AC-1: a function with no probe returns a DECLARED no_probe_registered
    verdict, never an implicit pass. Verified here against the real
    check_integration_edge entry point, not assumed."""
    monkeypatch.setattr(harness, "_devops_owned_names", lambda: (set(), []))
    result = harness.check_integration_edge("enceladus-some-unprobed-fn-gamma", {})
    assert result.state == harness.UNKNOWN
    assert result.reason_code == "no_probe_registered"
    assert result.state != harness.PASS


def test_p19_devops_owned_function_resolves_to_not_applicable_from_the_declaration():
    """AC-2: derived from the ownership DECLARATION, not a hardcoded name list."""
    names, errors = harness._devops_owned_names()
    assert not errors and names, "the pinned ownership snapshot must be readable"
    for devops_fn in sorted(names):
        result = harness.check_integration_edge(devops_fn, {})
        assert result.reason_code == "not_applicable_on_plane_devops_owned", devops_fn
        assert "NOT_APPLICABLE_ON_PLANE" in result.detail
        assert result.state == harness.UNKNOWN, "declared, but never a pass"
        # The rationale and its source are carried, not just a bare verdict.
        assert harness.DEVOPS_OWNERSHIP_SNAPSHOT_RELPATH in result.detail


def test_p19_ownership_predicate_is_exact_name_match_never_a_prefix():
    """AC-2's load-bearing detail. enceladus owns dozens of its own functions
    whose names START WITH 'devops-'. A startswith predicate would exempt
    every one of them -- including the very mart functions ENC-ISS-667 caught
    running dead -- and switch point 4 off exactly where it is needed."""
    names, _ = harness._devops_owned_names()
    enceladus_owned_devops_prefixed = "devops-governance-mart-gamma"
    assert enceladus_owned_devops_prefixed.startswith("devops-")
    assert enceladus_owned_devops_prefixed not in names, (
        "this function is enceladus-owned despite its devops- prefix")
    result = harness.check_integration_edge(enceladus_owned_devops_prefixed, {})
    assert result.reason_code != "not_applicable_on_plane_devops_owned", (
        "a devops- PREFIX must never confer the ownership exemption")


def test_p19_ownership_gate_fires_on_every_function_and_never_silently_skips(monkeypatch):
    """The gate STILL FIRES. A removed check is silence, and silence is what
    let a mart run dead and a schedule stop for fifteen days with every
    dashboard green."""
    calls = []

    def _spy():
        calls.append(1)
        return {"devops-io-devops-mcp"}, []

    monkeypatch.setattr(harness, "_devops_owned_names", _spy)
    for fn in ("devops-io-devops-mcp", "enceladus-anything-gamma"):
        result = harness.check_integration_edge(fn, {})
        # Either way a verdict is RECORDED -- never a skip, never a None.
        assert result is not None and result.point == 4
        assert result.state != harness.PASS
    assert len(calls) == 2, "ownership resolved on every function, not just some"


def test_p19_unreadable_ownership_declaration_is_unknown_not_assumed_non_devops(monkeypatch):
    """A missing declaration is a failure, never a silent pass and never a
    quiet 'assume it is ours and probe someone else's estate anyway'."""
    monkeypatch.setattr(harness, "_devops_owned_names",
                        lambda: (None, ["snapshot not found"]))
    result = harness.check_integration_edge("devops-io-devops-mcp", {})
    assert result.state == harness.UNKNOWN
    assert result.reason_code == "devops_ownership_declaration_unreadable"
    assert result.reason_code not in harness.ATTESTABLE_REASON_CODES


def test_p19_declared_ownership_still_passes_through_p08_remedy_3(monkeypatch):
    """ENC-TSK-P08's contradiction assertion is applied on EVERY path out of
    point 4, including the new ownership path. Preserved, not routed around."""
    monkeypatch.setattr(harness, "_devops_owned_names",
                        lambda: ({"devops-io-devops-mcp"}, []))
    point3 = harness.PointResult(3, "live_invocation", harness.FAIL, "boom",
                                  reason_code="function_error")
    result = harness.check_integration_edge(
        "devops-io-devops-mcp", {}, point3_result=point3)
    # The declared answer is UNKNOWN, so remedy 3 has nothing to override --
    # but it ran, and the verdict is still not a pass.
    assert result.state != harness.PASS


def test_p19_not_applicable_reaches_attested_never_an_unqualified_pass():
    """AC-2 rollup consequence: a declared ownership ceiling yields a named,
    determinate verdict -- and PASS stays structurally impossible."""
    report = harness.FunctionReport(
        function_name="devops-io-devops-mcp",
        points=[
            harness.PointResult(1, "artifact_identity", harness.PASS, "",
                                 reason_code="digest_match"),
            harness.PointResult(2, "layer_coherence", harness.PASS, "",
                                 reason_code="zero_layers"),
            harness.PointResult(3, "live_invocation", harness.PASS, "",
                                 reason_code="invoked_ok"),
            harness.PointResult(4, "integration_edge", harness.UNKNOWN, "NOT_APPLICABLE_ON_PLANE",
                                 reason_code="not_applicable_on_plane_devops_owned"),
            harness.PointResult(5, "ci_predicate_observed_failing", harness.PASS, "",
                                 reason_code="ci_history_confirmed_red"),
        ])
    assert report.overall == harness.ATTESTED
    assert report.overall != harness.PASS
    assert report.attested_points == [4]


# ---------------------------------------------------------------------------
# ENC-TSK-P20 -- the false-FAIL regression.
#
# Reproduces the LIVE defect exactly: the gamma API carries 184 routes and
# apigatewayv2 get_routes returns a bounded first page of 25. /approve landed
# in that page and /deny did not, so the probe reported
# FAIL "no escalation route found for /deny" against an API where the deny
# route exists and is guarded by the same authorizer as approve.
#
# A check that reports FAIL because it could not see everything is exactly as
# untrustworthy as one that reports PASS because it did not look. Both
# substitute the reach of the query for the state of the world.
# ---------------------------------------------------------------------------


def _escalation_api_paginated(page_size, filler_routes):
    """approve on page 1, deny pushed onto a later page behind filler."""
    routes = [{"RouteKey": f"{ESC_BASE}/approve", "AuthorizerId": "auth-esc"}]
    routes += [{"RouteKey": f"GET /api/v1/filler/{i}"} for i in range(filler_routes)]
    routes.append({"RouteKey": f"{ESC_BASE}/deny", "AuthorizerId": "auth-esc"})
    return FakeApiGatewayV2Client(
        apis=[{"ApiId": "api1"}],
        routes={"api1": routes},
        authorizers={
            "auth-esc": {"Name": "escalation",
                         "AuthorizerUri": f"arn:.../{ESC_FN}/invocations"},
        },
        page_size=page_size)


def test_p20_probe_paginates_and_does_not_false_fail_on_a_later_page_deny():
    """The regression. Unpaginated, this returned FAIL/no deny route found."""
    client = _escalation_api_paginated(page_size=25, filler_routes=200)
    state, detail = harness._probe_escalation_authorizer_routes(
        ESC_FN, {"apigatewayv2": client})
    assert state == harness.PASS, f"false FAIL reintroduced: {detail}"
    assert "/approve" in detail and "/deny" in detail


def test_p20_a_genuinely_missing_deny_route_still_fails_after_pagination():
    """The negative control. Pagination must not make the probe unable to fail.

    Fixing a false FAIL by making the check incapable of failing would be the
    ENC-ISS-665 vacuous pass rebuilt from the other direction.
    """
    routes = [{"RouteKey": f"{ESC_BASE}/approve", "AuthorizerId": "auth-esc"}]
    routes += [{"RouteKey": f"GET /api/v1/filler/{i}"} for i in range(200)]
    client = FakeApiGatewayV2Client(
        apis=[{"ApiId": "api1"}], routes={"api1": routes},
        authorizers={"auth-esc": {"Name": "escalation",
                                  "AuthorizerUri": f"arn:.../{ESC_FN}/invocations"}},
        page_size=25)
    state, detail = harness._probe_escalation_authorizer_routes(
        ESC_FN, {"apigatewayv2": client})
    assert state == harness.FAIL
    assert "/deny" in detail


def test_p20_pagination_error_is_unknown_never_a_determinate_verdict():
    """An enumeration that could not complete must not collapse to pass OR fail."""
    client = FakeApiGatewayV2Client(apis_error=RuntimeError("AccessDenied"))
    state, _ = harness._probe_escalation_authorizer_routes(
        ESC_FN, {"apigatewayv2": client})
    assert state == harness.UNKNOWN
