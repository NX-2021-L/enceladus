"""Offline tests for elr_lib.config -- profile resolution + secret masking.

No network access. Env vars are patched per-test via unittest.mock.patch.dict
and always restored.
"""

import unittest
from unittest.mock import patch

from elr_lib import config as elr_config


class InternalProfileMaskingTests(unittest.TestCase):
    def test_repr_never_contains_secret_value(self):
        secret = "SUPER-SECRET-VALUE-DO-NOT-LEAK-9f3a"
        with patch.dict("os.environ", {"ENCELADUS_COORDINATION_INTERNAL_API_KEY": secret}, clear=False):
            cfg = elr_config.InternalProfileConfig()
            rendered = repr(cfg)
        self.assertNotIn(secret, rendered)
        self.assertIn("keys_configured", rendered)

    def test_str_also_never_contains_secret_value(self):
        secret = "ANOTHER-SECRET-abcdef123456"
        with patch.dict("os.environ", {"COORDINATION_INTERNAL_API_KEY": secret}, clear=False):
            cfg = elr_config.InternalProfileConfig()
            rendered = str(cfg)
        self.assertNotIn(secret, rendered)

    def test_health_never_gets_a_key(self):
        with patch.dict(
            "os.environ",
            {
                "ENCELADUS_COORDINATION_INTERNAL_API_KEY": "some-key",
                "ENCELADUS_TRACKER_API_INTERNAL_API_KEY": "another-key",
            },
            clear=False,
        ):
            cfg = elr_config.InternalProfileConfig()
            self.assertEqual(cfg.key_for("health"), "")

    def test_dedicated_key_wins_over_common_chain(self):
        with patch.dict(
            "os.environ",
            {
                "ENCELADUS_TRACKER_API_INTERNAL_API_KEY": "dedicated-tracker-key",
                "ENCELADUS_COORDINATION_INTERNAL_API_KEY": "common-fallback-key",
            },
            clear=False,
        ):
            cfg = elr_config.InternalProfileConfig()
            self.assertEqual(cfg.key_for("tracker"), "dedicated-tracker-key")

    def test_common_chain_fallback_when_no_dedicated_key(self):
        with patch.dict(
            "os.environ",
            {"COORDINATION_INTERNAL_API_KEY": "fallback-key-value"},
            clear=False,
        ):
            cfg = elr_config.InternalProfileConfig()
            # governance/deploy has a dedicated env var name but it isn't set here,
            # so it should fall through to the common chain.
            self.assertEqual(cfg.key_for("governance"), "fallback-key-value")

    def test_checkout_reuses_tracker_key_chain(self):
        with patch.dict(
            "os.environ",
            {"ENCELADUS_TRACKER_API_INTERNAL_API_KEY": "tracker-key-for-checkout-too"},
            clear=False,
        ):
            cfg = elr_config.InternalProfileConfig()
            self.assertEqual(cfg.key_for("checkout"), "tracker-key-for-checkout-too")

    def test_base_url_defaults_match_server_py(self):
        cfg = elr_config.InternalProfileConfig()
        self.assertEqual(cfg.base_url("tracker"), "https://jreese.net/api/v1/tracker")
        self.assertEqual(cfg.base_url("coordination"), "https://jreese.net/api/v1/coordination")
        self.assertEqual(cfg.base_url("health"), "https://jreese.net/api/v1/health")
        self.assertEqual(
            cfg.base_url("graph_query"),
            "https://8nkzqkmxqc.execute-api.us-west-2.amazonaws.com/api/v1/tracker/graphsearch",
        )

    def test_base_url_env_override(self):
        with patch.dict("os.environ", {"ENCELADUS_TRACKER_API_BASE": "https://example.invalid/tracker"}, clear=False):
            cfg = elr_config.InternalProfileConfig()
            self.assertEqual(cfg.base_url("tracker"), "https://example.invalid/tracker")

    def test_unknown_api_raises(self):
        cfg = elr_config.InternalProfileConfig()
        with self.assertRaises(ValueError):
            cfg.base_url("not-a-real-api")
        with self.assertRaises(ValueError):
            cfg.key_for("not-a-real-api")


class McpHttpProfileMaskingTests(unittest.TestCase):
    def test_repr_never_contains_bearer_value(self):
        secret = "eyJhbGciOi.FAKE.JWT-SECRET-VALUE"
        with patch.dict("os.environ", {"ENCELADUS_MCP_BEARER_TOKEN": secret}, clear=False):
            cfg = elr_config.McpHttpProfileConfig()
            rendered = repr(cfg)
        self.assertNotIn(secret, rendered)
        self.assertIn("bearer=<set>", rendered)

    def test_bearer_unset_reports_unset(self):
        with patch.dict("os.environ", {}, clear=False):
            for key in elr_config.MCP_BEARER_ENV_CHAIN:
                __import__("os").environ.pop(key, None)
            cfg = elr_config.McpHttpProfileConfig()
        self.assertFalse(cfg.bearer_configured)
        self.assertIn("bearer=<unset>", repr(cfg))

    def test_gateway_url_default(self):
        cfg = elr_config.McpHttpProfileConfig()
        self.assertEqual(cfg.gateway_url, "https://jreese.net/api/v1/coordination/mcp")

    def test_gateway_url_env_override(self):
        with patch.dict("os.environ", {"ENCELADUS_MCP_GATEWAY_URL": "https://gateway.invalid/mcp"}, clear=False):
            cfg = elr_config.McpHttpProfileConfig()
            self.assertEqual(cfg.gateway_url, "https://gateway.invalid/mcp")

    def test_bearer_chain_priority(self):
        with patch.dict(
            "os.environ",
            {
                "ENCELADUS_MCP_BEARER_TOKEN": "primary-bearer",
                "ENCELADUS_MCP_API_KEY": "fallback-key",
            },
            clear=False,
        ):
            cfg = elr_config.McpHttpProfileConfig()
            self.assertEqual(cfg.bearer_token(), "primary-bearer")


class GetProfileTests(unittest.TestCase):
    def test_default_is_internal(self):
        cfg = elr_config.get_profile()
        self.assertIsInstance(cfg, elr_config.InternalProfileConfig)

    def test_explicit_internal(self):
        cfg = elr_config.get_profile("internal")
        self.assertIsInstance(cfg, elr_config.InternalProfileConfig)

    def test_mcp_http(self):
        cfg = elr_config.get_profile("mcp-http")
        self.assertIsInstance(cfg, elr_config.McpHttpProfileConfig)

    def test_unknown_profile_raises(self):
        with self.assertRaises(ValueError):
            elr_config.get_profile("not-a-real-profile")


if __name__ == "__main__":
    unittest.main()
