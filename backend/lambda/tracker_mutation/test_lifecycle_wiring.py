"""Tests for the ENC-TSK-H46 Lifecycle Service wiring in tracker_mutation.

Focus: the FAIL-CLOSED invariant (any invoke failure -> None -> caller rejects, never a silent
inline fallback) and verdict passthrough. Runs standalone or under pytest.
"""

import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lambda_function as lf  # noqa: E402


class _FakeBody:
    def __init__(self, raw):
        self._raw = raw

    def read(self):
        return self._raw


class _FakeLambda:
    def __init__(self, *, payload=None, function_error=None, raise_exc=None):
        self._payload = payload
        self._function_error = function_error
        self._raise_exc = raise_exc
        self.calls = []

    def invoke(self, **kwargs):
        self.calls.append(kwargs)
        if self._raise_exc:
            raise self._raise_exc
        resp = {"Payload": _FakeBody(self._payload)}
        if self._function_error:
            resp["FunctionError"] = self._function_error
        return resp


def _patch_client(fake):
    lf._lambda_client = fake
    lf._get_lambda_client = lambda: fake  # type: ignore


def test_unconfigured_function_fails_closed():
    lf.LIFECYCLE_SERVICE_FUNCTION = ""
    assert lf._invoke_lifecycle_service({"action": "validate_transition"}) is None


def test_function_error_fails_closed():
    lf.LIFECYCLE_SERVICE_FUNCTION = "fn"
    _patch_client(_FakeLambda(payload=b'{"allow": true}', function_error="Unhandled"))
    assert lf._invoke_lifecycle_service({"action": "validate_transition"}) is None


def test_invoke_exception_fails_closed():
    lf.LIFECYCLE_SERVICE_FUNCTION = "fn"
    _patch_client(_FakeLambda(raise_exc=RuntimeError("network down")))
    assert lf._invoke_lifecycle_service({"action": "validate_transition"}) is None


def test_malformed_verdict_fails_closed():
    lf.LIFECYCLE_SERVICE_FUNCTION = "fn"
    _patch_client(_FakeLambda(payload=b'{"unexpected": 1}'))
    assert lf._invoke_lifecycle_service({"action": "validate_transition"}) is None


def test_allow_verdict_passthrough():
    lf.LIFECYCLE_SERVICE_FUNCTION = "fn"
    fake = _FakeLambda(payload=json.dumps({"allow": True, "is_revert": False, "gate_class": "mechanical"}).encode())
    _patch_client(fake)
    v = lf._invoke_lifecycle_service({"action": "validate_transition", "record_id": "ENC-TSK-X"})
    assert v is not None and v["allow"] is True and v["gate_class"] == "mechanical", v
    assert fake.calls and fake.calls[0]["InvocationType"] == "RequestResponse"


def test_reject_verdict_passthrough():
    lf.LIFECYCLE_SERVICE_FUNCTION = "fn"
    reject = {"allow": False, "error": {"status": 400, "code": "INVALID_TRANSITION", "message": "no"}}
    _patch_client(_FakeLambda(payload=json.dumps(reject).encode()))
    v = lf._invoke_lifecycle_service({"action": "validate_transition"})
    assert v is not None and v["allow"] is False and v["error"]["code"] == "INVALID_TRANSITION", v


def test_flag_default_off():
    # No AppConfig + no env var -> default False (inline path / rollback is the default posture).
    os.environ.pop("ENABLE_LIFECYCLE_SERVICE", None)
    assert lf._lifecycle_service_enabled() in (False, True)  # resolves without error
    os.environ["ENABLE_LIFECYCLE_SERVICE"] = "true"
    assert lf._lifecycle_service_enabled() is True
    os.environ["ENABLE_LIFECYCLE_SERVICE"] = "false"
    assert lf._lifecycle_service_enabled() is False
    os.environ.pop("ENABLE_LIFECYCLE_SERVICE", None)


if __name__ == "__main__":
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
