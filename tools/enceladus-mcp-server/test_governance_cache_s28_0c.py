"""ENC-TSK-S28-0C: in-process governance cache keyed by hash, verified refetch, TTL probe."""
import importlib.util
import os
import pathlib
import sys
import uuid
from unittest.mock import patch

MODULE_PATH = pathlib.Path(__file__).with_name("server.py")
H1, H2 = "a" * 64, "b" * 64


def _load():
    name = f"enceladus_server_gov_cache_{uuid.uuid4().hex}"
    with patch.dict(os.environ, {"ENCELADUS_COMPACT_CONTEXT_ROUTE": "off", "GOVERNANCE_CACHE_PRELOAD": "0"}, clear=False):
        spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
        m = importlib.util.module_from_spec(spec)
        sys.modules[name] = m
        spec.loader.exec_module(m)
    return m


class _Source:
    """Scripted canonical record; counts reads."""

    def __init__(self, value):
        self.value, self.calls = value, 0

    def __call__(self):
        self.calls += 1
        return self.value


def _setup(value=H1):
    m = _load()
    src = _Source(value)
    m._get_canonical_governance_hash_ddb = src
    return m, src


def test_hit_path_makes_no_network_call():
    m, src = _setup()
    m._gov_cache_store(H1)
    assert m._require_governance_hash({"governance_hash": H1}) is None
    assert m._require_governance_hash({"governance_hash": H1}) is None
    assert src.calls == 0
    assert m._gov_cache_would_hit(H1)


def test_cold_cache_loads_once_then_hits():
    m, src = _setup()
    assert m._require_governance_hash({"governance_hash": H1}) is None
    assert m._require_governance_hash({"governance_hash": H1}) is None
    assert src.calls == 1


def test_mismatch_refetches_once_then_rejects():
    m, src = _setup(H1)
    m._gov_cache_store(H1)
    err = m._require_governance_hash({"governance_hash": H2})
    assert err and err.startswith("GOVERNANCE_STALE")
    assert src.calls == 1
    assert m._GOV_CACHE["hash"] == H1


def test_ttl_probe_refetches_after_expiry():
    m, src = _setup(H1)
    m._gov_cache_store(H1)
    m._GOV_CACHE["loaded_at"] -= m.GOVERNANCE_PROBE_TTL_S + 1
    assert not m._gov_cache_would_hit(H1)
    assert m._require_governance_hash({"governance_hash": H1}) is None
    assert src.calls == 1
    assert m._gov_cache_would_hit(H1)


def test_rotation_yields_zero_stale_acceptances():
    m, src = _setup(H1)
    m._gov_cache_store(H1)
    assert m._require_governance_hash({"governance_hash": H1}) is None
    # rotation happens; cache still fresh so old hash is accepted only until the probe is due
    src.value = H2
    m._GOV_CACHE["loaded_at"] -= m.GOVERNANCE_PROBE_TTL_S + 1
    err = m._require_governance_hash({"governance_hash": H1})
    assert err and err.startswith("GOVERNANCE_STALE")
    assert m._require_governance_hash({"governance_hash": H2}) is None
    err = m._require_governance_hash({"governance_hash": H1})
    assert err and err.startswith("GOVERNANCE_STALE")
    assert src.calls == 2  # probe + one mismatch refetch for the stale old hash; new hash hit the cache


def test_new_hash_after_rotation_accepted_via_mismatch_refetch():
    m, src = _setup(H1)
    m._gov_cache_store(H1)
    src.value = H2
    assert m._require_governance_hash({"governance_hash": H2}) is None
    assert src.calls == 1
    assert m._GOV_CACHE["hash"] == H2


def test_canonical_failure_falls_back_to_legacy_resolver():
    m = _load()

    def boom():
        raise RuntimeError("ddb down")

    m._get_canonical_governance_hash_ddb = boom
    m._get_governance_hash_via_api = lambda: H2
    m._gov_cache_store(H1)
    err = m._require_governance_hash({"governance_hash": H1, })
    assert err is None  # fresh hit, no refetch
    assert m._require_governance_hash({"governance_hash": H2}) is None
    assert m._GOV_CACHE["hash"] == H2
