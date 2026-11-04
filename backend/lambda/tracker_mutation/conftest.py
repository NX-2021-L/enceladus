"""ENC-TSK-S28-0D legacy-write shim.

Governed writes now commit via one transact_write_items (record + audit item +
counter + idempotency marker). Pre-S28 tests assert on the put_item /
update_item kwargs of the record write; this autouse fixture fans each
transaction's record Put/Update out to those calls (skipping the counter,
audit and marker rows) so those assertions keep verifying the composed
expressions. Test modules named *s28* exercise the native transaction and opt out.
"""
import importlib.util
import sys

import pytest
from botocore.exceptions import ClientError

# Test modules load lambda_function.py via importlib.module_from_spec without registering it in
# sys.modules; remember every module built that way so the fixture can reach it.
_LOADED = []
_orig_module_from_spec = importlib.util.module_from_spec


def _spy_module_from_spec(spec):
    mod = _orig_module_from_spec(spec)
    _LOADED.append(mod)
    return mod


importlib.util.module_from_spec = _spy_module_from_spec


def _fan_out(mod):
    def _commit(table, items, *a, **k):
        ddb = mod._get_ddb()
        for idx, op in enumerate(items):
            try:
                if "Put" in op:
                    put = dict(op["Put"])
                    pk = (put["Item"].get("project_id") or {}).get("S", "")
                    if pk.startswith(("audit#", "idem#")):
                        continue
                    ddb.put_item(**put)
                elif "Update" in op:
                    upd = dict(op["Update"])
                    if str((upd["Key"].get("record_id") or {}).get("S", "")).startswith("counter#"):
                        continue
                    ddb.update_item(**upd)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
                    raise
                reasons = [{"Code": "None"} for _ in items]
                reasons[idx] = {"Code": "ConditionalCheckFailed"}
                raise ClientError({"Error": {"Code": "TransactionCanceledException", "Message": "x"},
                                   "CancellationReasons": reasons}, "TransactWriteItems")
        return {}
    return _commit


@pytest.fixture(autouse=True)
def _s28_legacy_write_shim(request, monkeypatch):
    if "s28" in request.module.__name__:
        yield
        return
    for mod in list(sys.modules.values()) + _LOADED:
        if hasattr(mod, "_s28_commit") and hasattr(mod, "_s28_marker_put") and hasattr(mod, "_get_ddb"):
            monkeypatch.setattr(mod, "_s28_commit", _fan_out(mod))
            if hasattr(mod, "_s28_counter_observe"):  # pre-S28 tests stub allocation, not the counter table
                monkeypatch.setattr(mod, "_s28_counter_observe", lambda project_id, record_type, parent_root="": {
                    "key": {"project_id": {"S": project_id}, "record_id": {"S": "counter#stub"}},
                    "observed": 0, "exists": False})
    yield
