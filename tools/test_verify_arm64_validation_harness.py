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
    result = harness.check_artifact_identity(lam, s3, "fn", "arm64", "3.12", "abc123", bucket="bkt")
    assert result.state == harness.PASS


def test_point1_fail_on_digest_mismatch():
    lam = FakeLambdaClient(config={"Architectures": ["arm64"], "CodeSha256": "wrong-digest"})
    s3 = FakeS3Client(objects={("bkt", "lambda-artifacts/arm64-py3.12/fn-abc123.zip"): b"other-bytes"})
    result = harness.check_artifact_identity(lam, s3, "fn", "arm64", "3.12", "abc123", bucket="bkt")
    assert result.state == harness.FAIL


def test_point1_fail_on_wrong_architecture():
    lam = FakeLambdaClient(config={"Architectures": ["x86_64"], "CodeSha256": "irrelevant"})
    s3 = FakeS3Client()
    result = harness.check_artifact_identity(lam, s3, "fn", "arm64", "3.12", "abc123")
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
    result = harness.check_artifact_identity(lam, s3, "fn", "arm64", "3.12", "abc123")
    assert result.state == harness.UNKNOWN
    assert "denied" in result.detail.lower()
    assert result.reason_code == "permission_denied", (
        "an IAM denial must carry the machine-readable permission_denied code, not just prose, "
        "so a fleet-wide aggregator can distinguish it from every other kind of unknown"
    )


def test_point1_unknown_not_pass_when_config_read_fails():
    lam = FakeLambdaClient(config_error=Exception("Throttled"))
    s3 = FakeS3Client()
    result = harness.check_artifact_identity(lam, s3, "fn", "arm64", "3.12", "abc123")
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
    class FakeLogs:
        def describe_log_streams(self, **kwargs):
            return {"logStreams": [{"logStreamName": "s1", "lastEventTimestamp": 0}]}

        def get_log_events(self, **kwargs):  # pragma: no cover - not reached (stale short-circuits)
            return {"events": []}

    state, detail = harness._probe_governance_mart_schedule("devops-recompute-governance", {"logs": FakeLogs()})
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
        lam, FakeS3Client(get_error=_DENIED), "fn", "arm64", "3.12", "abc123",
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
        lam, FakeS3Client(get_error=_DENIED), "fn", "arm64", "3.12", "abc123",
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
        lam, FakeS3Client(get_error=_DENIED), "fn", "arm64", "3.12", "abc123",
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
    result = harness.check_artifact_identity(lam, s3, "fn", "arm64", "3.12", "abc123", bucket="bkt")
    assert result.state == harness.PASS
    assert result.substitute is None


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
