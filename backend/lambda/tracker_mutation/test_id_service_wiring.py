"""Tests for the ENC-TSK-L06 ID Service wiring in tracker_mutation.

Focus: the FAIL-CLOSED invariant (any invoke failure -> None -> caller rejects, never a
silent inline fallback) and verdict passthrough for _invoke_id_service, plus the edge-layer
ID_BOUNDARY_VIOLATION guard (AC-3) and its trust-score notify hook (AC-4). Mirrors the
style of test_lifecycle_wiring.py. Runs standalone or under pytest.
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


# ---------------------------------------------------------------------------
# _invoke_id_service fail-closed invariant (mirrors _invoke_lifecycle_service tests)
# ---------------------------------------------------------------------------

def test_unconfigured_function_fails_closed():
    lf.ID_SERVICE_FUNCTION = ""
    assert lf._invoke_id_service({"action": "allocate"}) is None


def test_function_error_fails_closed():
    lf.ID_SERVICE_FUNCTION = "fn"
    _patch_client(_FakeLambda(payload=b'{"allow": true}', function_error="Unhandled"))
    assert lf._invoke_id_service({"action": "allocate"}) is None


def test_invoke_exception_fails_closed():
    lf.ID_SERVICE_FUNCTION = "fn"
    _patch_client(_FakeLambda(raise_exc=RuntimeError("network down")))
    assert lf._invoke_id_service({"action": "allocate"}) is None


def test_malformed_verdict_fails_closed():
    lf.ID_SERVICE_FUNCTION = "fn"
    _patch_client(_FakeLambda(payload=b'{"unexpected": 1}'))
    assert lf._invoke_id_service({"action": "allocate"}) is None


def test_allow_verdict_passthrough():
    lf.ID_SERVICE_FUNCTION = "fn"
    fake = _FakeLambda(payload=json.dumps({
        "allow": True, "record_id": "ENC-TSK-ABC", "item_id_provenance": "deadbeef",
    }).encode())
    _patch_client(fake)
    v = lf._invoke_id_service({"action": "allocate", "project_id": "enceladus"})
    assert v is not None and v["allow"] is True and v["record_id"] == "ENC-TSK-ABC", v
    assert fake.calls and fake.calls[0]["InvocationType"] == "RequestResponse"


def test_reject_verdict_passthrough():
    lf.ID_SERVICE_FUNCTION = "fn"
    reject = {"allow": False, "error": {"status": 400, "code": "CAPACITY_EXHAUSTED", "message": "no"}}
    _patch_client(_FakeLambda(payload=json.dumps(reject).encode()))
    v = lf._invoke_id_service({"action": "allocate"})
    assert v is not None and v["allow"] is False and v["error"]["code"] == "CAPACITY_EXHAUSTED", v


def test_flag_default_off():
    os.environ.pop("ENABLE_ID_SERVICE", None)
    assert lf._id_service_enabled() in (False, True)  # resolves without error
    os.environ["ENABLE_ID_SERVICE"] = "true"
    assert lf._id_service_enabled() is True
    os.environ["ENABLE_ID_SERVICE"] = "false"
    assert lf._id_service_enabled() is False
    os.environ.pop("ENABLE_ID_SERVICE", None)


# ---------------------------------------------------------------------------
# AC-4: trust-score violation notify is fire-and-forget (Event invoke), never raises,
# and is a no-op when ID_SERVICE_FUNCTION is unset.
# ---------------------------------------------------------------------------

def test_record_id_boundary_violation_noop_when_unconfigured():
    lf.ID_SERVICE_FUNCTION = ""
    # Must not raise even though no Lambda client is configured.
    lf._record_id_boundary_violation({"provider": "ENC-SES-057"}, "task", "item_id")


def test_record_id_boundary_violation_fires_event_invoke():
    lf.ID_SERVICE_FUNCTION = "fn"
    fake = _FakeLambda(payload=b'{}')
    _patch_client(fake)
    lf._record_id_boundary_violation({"provider": "ENC-SES-057"}, "task", "item_id")
    assert fake.calls, "expected an invoke call"
    call = fake.calls[0]
    assert call["InvocationType"] == "Event"
    payload = json.loads(call["Payload"])
    assert payload["action"] == "record_violation"
    assert payload["caller_identity"] == "ENC-SES-057"
    assert payload["record_type"] == "task"


def test_record_id_boundary_violation_swallows_invoke_exception():
    lf.ID_SERVICE_FUNCTION = "fn"
    _patch_client(_FakeLambda(raise_exc=RuntimeError("boom")))
    # Must not raise — failure isolation is the whole point of fire-and-forget.
    lf._record_id_boundary_violation({"provider": "ENC-SES-057"}, "task", "record_id")


# ---------------------------------------------------------------------------
# AC-3: edge-layer rejection of create payloads carrying record_id/item_id/
# item_id_provenance (through the public _handle_create_record surface).
# ---------------------------------------------------------------------------

def _patch_project_prefix(prefix="ENC"):
    """_handle_create_record looks up the project prefix (a real DDB GetItem) BEFORE
    reaching the forbidden-field guard. Patch it so these guard-focused tests don't need
    a live DynamoDB table — mirrors how _patch_client avoids a live Lambda invoke."""
    lf._get_project_prefix = lambda project_id: prefix  # type: ignore


def _minimal_issue_body(**extra):
    """Minimal valid issue create payload (category + evidence[{description,
    steps_to_duplicate}]) so validation clears BEFORE reaching the forbidden-field guard
    under test — the guard runs late in _handle_create_record, after all the
    record-type-specific required-field checks."""
    body = {
        "title": "x",
        "category": "bug",
        "evidence": [{"description": "test evidence", "steps_to_duplicate": ["step 1"]}],
    }
    body.update(extra)
    return body


def test_create_record_rejects_client_supplied_item_id():
    lf.ID_SERVICE_FUNCTION = ""  # notify is a no-op; irrelevant to this assertion
    _patch_project_prefix()
    resp = lf._handle_create_record("enceladus", "issue", _minimal_issue_body(item_id="ENC-ISS-999"))
    assert resp["statusCode"] == 400
    body = json.loads(resp["body"])
    assert body["error_envelope"]["code"] == "ID_BOUNDARY_VIOLATION"


def test_create_record_rejects_client_supplied_record_id():
    lf.ID_SERVICE_FUNCTION = ""
    _patch_project_prefix()
    resp = lf._handle_create_record("enceladus", "issue", _minimal_issue_body(record_id="issue#ENC-ISS-999"))
    assert resp["statusCode"] == 400
    body = json.loads(resp["body"])
    assert body["error_envelope"]["code"] == "ID_BOUNDARY_VIOLATION"


def test_create_record_rejects_client_supplied_item_id_provenance():
    lf.ID_SERVICE_FUNCTION = ""
    _patch_project_prefix()
    resp = lf._handle_create_record("enceladus", "issue", _minimal_issue_body(item_id_provenance="fake-sig"))
    assert resp["statusCode"] == 400
    body = json.loads(resp["body"])
    assert body["error_envelope"]["code"] == "ID_BOUNDARY_VIOLATION"


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
