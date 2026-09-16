"""Offline tests for elr_lib.profiles (ENC-TSK-P77, T-B4, FR-B4-10):
environment-profile selection by explicit name, env var, and default;
unknown-profile fail-fast; and the per-API base-URL override table.
"""

import os
import unittest
from unittest.mock import patch

from elr_lib import config as elr_config
from elr_lib import profiles as elr_profiles


class GetEnvironmentProfileTests(unittest.TestCase):
    def test_default_is_prod_when_nothing_set(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(elr_profiles.ENV_PROFILE_ENV_VAR, None)
            profile = elr_profiles.get_environment_profile()
        self.assertEqual(profile.name, "prod")
        self.assertEqual(profile.mcp_base_url, "https://mcp.jreese.net")
        self.assertEqual(profile.coordination_base_url, "https://jreese.net/api/v1/coordination")

    def test_explicit_name_selects_v4_gamma(self):
        profile = elr_profiles.get_environment_profile("v4-gamma")
        self.assertEqual(profile.name, "v4-gamma")
        self.assertEqual(profile.mcp_base_url, "https://mcp-gamma.jreese.net")
        self.assertEqual(profile.coordination_base_url, "https://enceladus-gamma.jreese.net/api/v1/coordination")

    def test_env_var_selects_when_no_explicit_name(self):
        with patch.dict(os.environ, {elr_profiles.ENV_PROFILE_ENV_VAR: "v4-gamma"}):
            profile = elr_profiles.get_environment_profile(None)
        self.assertEqual(profile.name, "v4-gamma")

    def test_explicit_name_wins_over_env_var(self):
        with patch.dict(os.environ, {elr_profiles.ENV_PROFILE_ENV_VAR: "v4-gamma"}):
            profile = elr_profiles.get_environment_profile("prod")
        self.assertEqual(profile.name, "prod")

    def test_unknown_profile_fails_fast_listing_valid_names(self):
        with self.assertRaises(ValueError) as ctx:
            elr_profiles.get_environment_profile("staging")
        message = str(ctx.exception)
        self.assertIn("staging", message)
        self.assertIn("prod", message)
        self.assertIn("v4-gamma", message)

    def test_unknown_env_var_value_fails_fast(self):
        with patch.dict(os.environ, {elr_profiles.ENV_PROFILE_ENV_VAR: "not-real"}):
            with self.assertRaises(ValueError):
                elr_profiles.get_environment_profile(None)

    def test_api_base_overrides_mirror_prod_table_on_gamma_host(self):
        gamma = elr_profiles.get_environment_profile("v4-gamma")
        prod = elr_profiles.get_environment_profile("prod")
        for api in ("coordination", "document", "deploy", "changelog", "tracker", "checkout", "governance", "health", "github"):
            self.assertTrue(prod.api_base_overrides[api].startswith("https://jreese.net/"))
            self.assertTrue(gamma.api_base_overrides[api].startswith("https://enceladus-gamma.jreese.net/"))
            # Same path suffix on both hosts.
            prod_suffix = prod.api_base_overrides[api].split("jreese.net", 1)[1]
            gamma_suffix = gamma.api_base_overrides[api].split("jreese.net", 1)[1]
            self.assertEqual(prod_suffix, gamma_suffix)

    def test_graph_query_intentionally_excluded_from_overrides(self):
        gamma = elr_profiles.get_environment_profile("v4-gamma")
        self.assertNotIn("graph_query", gamma.api_base_overrides)


class InternalProfileConfigEnvironmentThreadingTests(unittest.TestCase):
    """AC-1: config.py's INTERNAL base-URL table picks up environment
    profile overrides, but an explicit ENCELADUS_<API>_API_BASE always wins.
    """

    def test_default_prod_matches_pre_existing_hardcoded_defaults(self):
        # Byte-for-byte unchanged behavior for the default profile (AC-2:
        # "a single-profile run is unchanged apart from the new fields").
        with patch.dict(os.environ, {}, clear=False):
            for key in list(os.environ):
                if key.startswith("ENCELADUS_") or key == "CHECKOUT_SERVICE_API_BASE":
                    os.environ.pop(key, None)
            cfg = elr_config.InternalProfileConfig()
        self.assertEqual(cfg.base_url("tracker"), "https://jreese.net/api/v1/tracker")
        self.assertEqual(cfg.base_url("document"), "https://jreese.net/api/v1/documents")
        self.assertEqual(
            cfg.base_url("graph_query"),
            "https://8nkzqkmxqc.execute-api.us-west-2.amazonaws.com/api/v1/tracker/graphsearch",
        )

    def test_v4_gamma_environment_profile_overrides_bases(self):
        gamma = elr_profiles.get_environment_profile("v4-gamma")
        with patch.dict(os.environ, {}, clear=False):
            for key in list(os.environ):
                if key.startswith("ENCELADUS_") or key == "CHECKOUT_SERVICE_API_BASE":
                    os.environ.pop(key, None)
            cfg = elr_config.InternalProfileConfig(environment_profile=gamma)
        self.assertEqual(cfg.base_url("tracker"), "https://enceladus-gamma.jreese.net/api/v1/tracker")
        self.assertEqual(cfg.base_url("document"), "https://enceladus-gamma.jreese.net/api/v1/documents")
        self.assertEqual(cfg.environment_profile.name, "v4-gamma")
        # graph_query has no gamma override -- falls back to the static
        # (prod) default, documented as a known gap.
        self.assertEqual(
            cfg.base_url("graph_query"),
            "https://8nkzqkmxqc.execute-api.us-west-2.amazonaws.com/api/v1/tracker/graphsearch",
        )

    def test_explicit_env_var_wins_over_environment_profile(self):
        gamma = elr_profiles.get_environment_profile("v4-gamma")
        with patch.dict(os.environ, {"ENCELADUS_TRACKER_API_BASE": "https://override.invalid/tracker"}):
            cfg = elr_config.InternalProfileConfig(environment_profile=gamma)
        self.assertEqual(cfg.base_url("tracker"), "https://override.invalid/tracker")

    def test_get_profile_threads_environment_profile_name(self):
        with patch.dict(os.environ, {}, clear=False):
            for key in list(os.environ):
                if key.startswith("ENCELADUS_") or key == "CHECKOUT_SERVICE_API_BASE":
                    os.environ.pop(key, None)
            cfg = elr_config.get_profile("internal", environment_profile_name="v4-gamma")
        self.assertEqual(cfg.base_url("tracker"), "https://enceladus-gamma.jreese.net/api/v1/tracker")

    def test_get_profile_rejects_unknown_environment_profile(self):
        with self.assertRaises(ValueError):
            elr_config.get_profile("internal", environment_profile_name="staging")

    def test_mcp_http_gateway_url_derives_from_environment_profile(self):
        gamma = elr_profiles.get_environment_profile("v4-gamma")
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ENCELADUS_MCP_GATEWAY_URL", None)
            cfg = elr_config.McpHttpProfileConfig(environment_profile=gamma)
        self.assertEqual(cfg.gateway_url, "https://enceladus-gamma.jreese.net/api/v1/coordination/mcp")


if __name__ == "__main__":
    unittest.main()
