"""ENC-TSK-I30: governance URI dual-key determinism.

Proves the content-hash input key for ``governance://agents.md`` equals the key
``read_resource`` serves: the legacy nested ``agents/agents.md`` is treated as an
alias (no phantom ``governance://agents/agents.md`` URI), and the canonical
top-level ``agents.md`` wins regardless of S3 listing order — so a §13 write and the
content hash can never diverge through a dedup mask (ENC-FTR-116 / ENC-ISS-390).
"""

import asyncio
import importlib.util
import io
import pathlib
import sys
from unittest.mock import patch

MODULE_PATH = pathlib.Path(__file__).with_name("server.py")
SPEC = importlib.util.spec_from_file_location("enceladus_server_i30", MODULE_PATH)
server = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = server
SPEC.loader.exec_module(server)


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class _ListingS3:
    """Fake S3 returning a fixed prefix listing plus per-key bodies."""

    def __init__(self, bodies: dict, *, order: list):
        self.bodies = bodies        # {s3_key: text}
        self.order = order          # s3_keys in list_objects_v2 enumeration order
        self.get_calls: list = []

    def list_objects_v2(self, **kwargs):
        prefix = kwargs.get("Prefix", "")
        contents = [
            {"Key": k, "LastModified": "2026-06-27T00:00:00Z"}
            for k in self.order
            if k.startswith(prefix)
        ]
        return {"Contents": contents, "IsTruncated": False}

    def get_object(self, **kwargs):
        key = kwargs["Key"]
        self.get_calls.append(key)
        if key not in self.bodies:
            raise RuntimeError(f"NoSuchKey: {key}")
        return {"Body": io.BytesIO(self.bodies[key].encode("utf-8"))}


def _reset_caches():
    server._governance_catalog_cache = {}
    server._governance_catalog_cached_at = 0.0
    server._governance_resource_body_cache.clear()


PREFIX = server.S3_GOVERNANCE_PREFIX.rstrip("/")
CANON = f"{PREFIX}/agents.md"
ALIAS = f"{PREFIX}/agents/agents.md"


def test_uri_mapping_aliases_nested_agents_to_canonical():
    assert server._governance_uri_from_file_name("agents.md") == "governance://agents.md"
    # ENC-TSK-I30: nested alias maps to the canonical URI, not a phantom URI.
    assert server._governance_uri_from_file_name("agents/agents.md") == "governance://agents.md"
    # legitimate agents/ subdir files are unaffected.
    assert (
        server._governance_uri_from_file_name("agents/plan-capture.md")
        == "governance://agents/plan-capture.md"
    )


def test_canonical_rel_for_uri():
    assert server._governance_canonical_rel_for_uri("governance://agents.md") == "agents.md"
    assert (
        server._governance_canonical_rel_for_uri("governance://agents/plan-capture.md")
        == "agents/plan-capture.md"
    )


def test_catalog_prefers_canonical_key_both_orders():
    """Canonical top-level agents.md wins regardless of S3 listing order; no phantom URI."""
    bodies = {CANON: "# canonical agents", ALIAS: "# legacy nested"}
    for order in ([CANON, ALIAS], [ALIAS, CANON]):
        _reset_caches()
        fake = _ListingS3(bodies, order=order)
        with patch.object(server, "_get_s3", return_value=fake):
            catalog = server._governance_catalog_from_s3()
        assert "governance://agents.md" in catalog
        assert "governance://agents/agents.md" not in catalog, "phantom URI must not exist"
        assert catalog["governance://agents.md"]["s3_key"] == CANON, f"order={order}"


def test_hash_input_bytes_equal_read_resource_bytes():
    """The bytes the hash folds in for governance://agents.md == the governance.get bytes."""
    bodies = {CANON: "# canonical agents body", ALIAS: "# legacy nested body"}
    _reset_caches()
    fake = _ListingS3(bodies, order=[CANON, ALIAS])
    with patch.object(server, "_get_s3", return_value=fake):
        catalog = server._governance_catalog_from_s3()
        hash_key = catalog["governance://agents.md"]["s3_key"]  # key folded into the hash
        served = _run(server.read_resource("governance://agents.md"))  # governance.get bytes
    assert hash_key == CANON
    assert served == bodies[hash_key] == "# canonical agents body"


def test_only_nested_alias_present_is_consistent():
    """If only the legacy nested key exists, hash and read still agree on the same bytes."""
    bodies = {ALIAS: "# only nested"}
    _reset_caches()
    fake = _ListingS3(bodies, order=[ALIAS])
    with patch.object(server, "_get_s3", return_value=fake):
        catalog = server._governance_catalog_from_s3()
        assert catalog["governance://agents.md"]["s3_key"] == ALIAS  # aliased, no phantom
        served = _run(server.read_resource("governance://agents.md"))
    # read_resource tries canonical agents.md first (NoSuchKey), then the alias.
    assert served == bodies[catalog["governance://agents.md"]["s3_key"]] == "# only nested"


if __name__ == "__main__":
    import traceback

    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"[PASS] {name}")
            except Exception:  # noqa: BLE001
                failures += 1
                print(f"[FAIL] {name}")
                traceback.print_exc()
    sys.exit(1 if failures else 0)
