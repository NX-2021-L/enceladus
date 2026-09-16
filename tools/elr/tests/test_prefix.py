"""Offline tests for elr_lib.prefix (ENC-TSK-P90 / T-B1b, FR-B4-3) -- the
live projects.prefix_map resolver: network resolution, the 300s-TTL local
file cache (fresh-cache short-circuit and stale-cache-on-network-failure
fallback), the built-in last-resort seed, and never-guess unclassified
behavior. No network access -- elr_lib.prefix.McpHttpClient is mocked
directly (no urlopen involved) so these stay fast and deterministic.
"""

import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from elr_lib import prefix as elr_prefix
from elr_lib.prefix import PrefixResolver


def _tool_result(*, status=200, result=None, is_error=False):
    return SimpleNamespace(status=status, result=result, is_error=is_error)


class ExtractPrefixTests(unittest.TestCase):
    def test_extracts_leading_prefix(self):
        self.assertEqual(elr_prefix.extract_prefix("ENC-TSK-1"), "ENC")

    def test_normalizes_case_and_whitespace(self):
        self.assertEqual(elr_prefix.extract_prefix("  int-tsk-4  "), "INT")

    def test_no_prefix_shape_returns_none(self):
        # No hyphen at all -- nothing that looks like a PREFIX- segment.
        self.assertIsNone(elr_prefix.extract_prefix("garbage"))
        # Leading digit can never be part of a [A-Z]{2,8} prefix segment.
        self.assertIsNone(elr_prefix.extract_prefix("123-TSK-1"))

    def test_empty_returns_none(self):
        self.assertIsNone(elr_prefix.extract_prefix(""))
        self.assertIsNone(elr_prefix.extract_prefix(None))


class FromMappingTests(unittest.TestCase):
    def test_from_mapping_never_touches_network_or_disk(self):
        with patch("elr_lib.prefix.McpHttpClient") as mock_cls:
            resolver = PrefixResolver.from_mapping({"ENC": "enceladus"})
            self.assertEqual(resolver.resolve_prefix("ENC-TSK-1"), "enceladus")
        mock_cls.assert_not_called()

    def test_source_defaults_to_none(self):
        resolver = PrefixResolver.from_mapping({"ENC": "enceladus"})
        self.assertEqual(resolver.source, elr_prefix.SOURCE_NONE)


class UnclassifiedReportingTests(unittest.TestCase):
    def test_prefix_absent_from_map_returns_none_never_a_guess(self):
        resolver = PrefixResolver.from_mapping({"ENC": "enceladus"})
        self.assertIsNone(resolver.resolve_prefix("ZZZ-TSK-100"))

    def test_no_prefix_shape_returns_none_without_touching_map(self):
        with patch("elr_lib.prefix.McpHttpClient") as mock_cls:
            resolver = PrefixResolver(cache_path=Path("/nonexistent/does/not/matter.json"))
            self.assertIsNone(resolver.resolve_prefix("garbage"))
        # Never fetched -- no prefix segment means nothing to resolve.
        mock_cls.assert_not_called()
        self.assertEqual(resolver.source, elr_prefix.SOURCE_NONE)


class NetworkResolutionTests(unittest.TestCase):
    def test_successful_network_fetch_is_used_and_cached(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "prefix_map.json"
            fake_result = {"prefixes": {"ENC": "enceladus", "DVP": "devops"}, "source": "x", "generated_at": "z"}
            with patch("elr_lib.prefix.McpHttpClient") as mock_cls:
                mock_cls.return_value.call_tool.return_value = _tool_result(result=fake_result)
                resolver = PrefixResolver(cache_path=cache_path, timeout=5)
                project_id = resolver.resolve_prefix("DVP-TSK-1")

            self.assertEqual(project_id, "devops")
            self.assertEqual(resolver.source, elr_prefix.SOURCE_NETWORK)
            # tools/call was issued with the exact contract shape.
            mock_cls.return_value.call_tool.assert_called_once_with(
                "search", {"action": "projects.prefix_map", "arguments": {}}
            )
            # The successful fetch refreshes the local cache file.
            written = json.loads(cache_path.read_text())
            self.assertEqual(written["prefixes"], {"ENC": "enceladus", "DVP": "devops"})
            self.assertIn("generated_at", written)

    def test_fetched_once_per_resolver_instance(self):
        """Two resolve_prefix() calls on the same instance must only hit
        the network once ("fetched once per run")."""
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "prefix_map.json"
            fake_result = {"prefixes": {"ENC": "enceladus"}, "source": "x", "generated_at": "z"}
            with patch("elr_lib.prefix.McpHttpClient") as mock_cls:
                mock_cls.return_value.call_tool.return_value = _tool_result(result=fake_result)
                resolver = PrefixResolver(cache_path=cache_path, timeout=5)
                resolver.resolve_prefix("ENC-TSK-1")
                resolver.resolve_prefix("ENC-ISS-2")
            self.assertEqual(mock_cls.return_value.call_tool.call_count, 1)

    def test_malformed_network_response_falls_through_to_builtin(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "prefix_map.json"
            with patch("elr_lib.prefix.McpHttpClient") as mock_cls:
                mock_cls.return_value.call_tool.return_value = _tool_result(result={"not_prefixes": True})
                resolver = PrefixResolver(cache_path=cache_path, timeout=5)
                resolver.resolve_prefix("ENC-TSK-1")
            self.assertEqual(resolver.source, elr_prefix.SOURCE_BUILTIN)
            self.assertIn("prefix_map_builtin_seed_used", resolver.anomalies)

    def test_error_status_falls_through_to_builtin(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "prefix_map.json"
            with patch("elr_lib.prefix.McpHttpClient") as mock_cls:
                mock_cls.return_value.call_tool.return_value = _tool_result(status=500, result=None, is_error=True)
                resolver = PrefixResolver(cache_path=cache_path, timeout=5)
                resolver.resolve_prefix("ENC-TSK-1")
            self.assertEqual(resolver.source, elr_prefix.SOURCE_BUILTIN)
            self.assertTrue(any("prefix_map_network_failed" in a for a in resolver.anomalies))


class CacheTests(unittest.TestCase):
    def _write_cache(self, cache_path, prefixes, generated_at):
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps({"prefixes": prefixes, "generated_at": generated_at}))

    def test_fresh_cache_is_used_without_any_network_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "prefix_map.json"
            self._write_cache(cache_path, {"ENC": "enceladus", "INT": "internal-tools"}, time.time())

            with patch("elr_lib.prefix.McpHttpClient") as mock_cls:
                resolver = PrefixResolver(cache_path=cache_path, timeout=5, cache_ttl_seconds=300)
                project_id = resolver.resolve_prefix("INT-TSK-1")

            self.assertEqual(project_id, "internal-tools")
            self.assertEqual(resolver.source, elr_prefix.SOURCE_CACHE)
            mock_cls.assert_not_called()

    def test_stale_cache_triggers_network_attempt_first(self):
        """A cache older than the TTL is not used blindly -- a fresh
        network fetch is attempted first; only on failure does the stale
        file get used (see next test)."""
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "prefix_map.json"
            self._write_cache(cache_path, {"ENC": "enceladus"}, time.time() - 10_000)
            fake_result = {"prefixes": {"ENC": "enceladus", "DVP": "devops"}, "source": "x", "generated_at": "z"}

            with patch("elr_lib.prefix.McpHttpClient") as mock_cls:
                mock_cls.return_value.call_tool.return_value = _tool_result(result=fake_result)
                resolver = PrefixResolver(cache_path=cache_path, timeout=5, cache_ttl_seconds=300)
                project_id = resolver.resolve_prefix("DVP-TSK-1")

            self.assertEqual(project_id, "devops")
            self.assertEqual(resolver.source, elr_prefix.SOURCE_NETWORK)
            mock_cls.return_value.call_tool.assert_called_once()

    def test_stale_cache_used_when_network_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "prefix_map.json"
            self._write_cache(cache_path, {"ENC": "enceladus", "DVP": "devops"}, time.time() - 10_000)

            with patch("elr_lib.prefix.McpHttpClient") as mock_cls:
                mock_cls.return_value.call_tool.return_value = _tool_result(status=0, result=None, is_error=True)
                resolver = PrefixResolver(cache_path=cache_path, timeout=5, cache_ttl_seconds=300)
                project_id = resolver.resolve_prefix("DVP-TSK-1")

            self.assertEqual(project_id, "devops")
            self.assertEqual(resolver.source, elr_prefix.SOURCE_CACHE)
            self.assertIn("prefix_map_stale_cache_used", resolver.anomalies)

    def test_corrupt_cache_file_is_ignored_like_no_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "prefix_map.json"
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text("{not valid json")

            with patch("elr_lib.prefix.McpHttpClient") as mock_cls:
                mock_cls.return_value.call_tool.return_value = _tool_result(status=0, result=None, is_error=True)
                resolver = PrefixResolver(cache_path=cache_path, timeout=5, cache_ttl_seconds=300)
                resolver.resolve_prefix("ENC-TSK-1")

            # No usable cache and network failed -> builtin last resort.
            self.assertEqual(resolver.source, elr_prefix.SOURCE_BUILTIN)


class BuiltinLastResortTests(unittest.TestCase):
    def test_builtin_seed_used_when_no_network_and_no_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "does-not-exist" / "prefix_map.json"
            with patch("elr_lib.prefix.McpHttpClient") as mock_cls:
                mock_cls.return_value.call_tool.return_value = _tool_result(status=0, result=None, is_error=True)
                resolver = PrefixResolver(cache_path=cache_path, timeout=5)
                project_id = resolver.resolve_prefix("ENC-TSK-1")

            self.assertEqual(project_id, "enceladus")
            self.assertEqual(resolver.source, elr_prefix.SOURCE_BUILTIN)
            self.assertIn("prefix_map_builtin_seed_used", resolver.anomalies)

    def test_builtin_seed_has_no_other_prefixes(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "prefix_map.json"
            with patch("elr_lib.prefix.McpHttpClient") as mock_cls:
                mock_cls.return_value.call_tool.return_value = _tool_result(status=0, result=None, is_error=True)
                resolver = PrefixResolver(cache_path=cache_path, timeout=5)
                self.assertIsNone(resolver.resolve_prefix("DVP-TSK-1"))
            self.assertEqual(resolver.source, elr_prefix.SOURCE_BUILTIN)


class ModuleLevelResolvePrefixTests(unittest.TestCase):
    def test_free_function_builds_a_throwaway_resolver(self):
        resolver = PrefixResolver.from_mapping({"ENC": "enceladus"})
        self.assertEqual(elr_prefix.resolve_prefix("ENC-TSK-1", resolver=resolver), "enceladus")


if __name__ == "__main__":
    unittest.main()
