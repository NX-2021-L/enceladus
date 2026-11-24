#!/usr/bin/env python3
"""Self-test: the F-12 guard passes the real template and FAILS on each weakening."""
import copy
import sys
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_mcp_signin_client as c  # noqa: E402


def _real():
    with open(c.TEMPLATE, encoding="utf-8") as fh:
        return yaml.load(fh, Loader=c._Loader)


def _props(doc):
    return doc["Resources"][c.RESOURCE]["Properties"]


class T(unittest.TestCase):
    def mutate(self, fn):
        doc = copy.deepcopy(_real())
        fn(_props(doc))
        return c.check_doc(doc)

    def assertFails(self, errs, needle):
        self.assertTrue(any(needle in e for e in errs), errs)

    def test_real_template_passes(self):
        self.assertEqual(c.check(), [])

    def test_loader_sees_both_if_branches(self):
        cbs = _props(_real())["CallbackURLs"]
        self.assertEqual(sorted(c._callback_leaves(cbs[0])), sorted(c.ALLOWED_CALLBACKS))

    def test_forbidden_flows_fail(self):
        for flow in c.FORBIDDEN_AUTH_FLOWS:
            errs = self.mutate(lambda p, f=flow: p["ExplicitAuthFlows"].append(f))
            self.assertFails(errs, f"must not contain {flow}")
            self.assertFails(errs, "ExplicitAuthFlows must be exactly")

    def test_other_extra_flow_fails(self):
        self.assertFails(self.mutate(lambda p: p["ExplicitAuthFlows"].append("ALLOW_USER_SRP_AUTH")), "ExplicitAuthFlows")

    def test_generate_secret_true_fails(self):
        self.assertFails(self.mutate(lambda p: p.update(GenerateSecret=True)), "GenerateSecret")

    def test_generate_secret_missing_fails(self):
        self.assertFails(self.mutate(lambda p: p.pop("GenerateSecret")), "GenerateSecret")

    def test_foreign_callback_fails(self):
        for url in ("https://claude.ai/api/mcp/auth_callback", "http://localhost:8787/callback", "https://mcp.jreese.net/*"):
            self.assertFails(self.mutate(lambda p, u=url: p["CallbackURLs"].append(u)), "CallbackURLs entry")

    def test_foreign_callback_inside_if_fails(self):
        def f(p):
            p["CallbackURLs"][0]["Fn::If"][2] = "https://evil.example/callback"
        self.assertFails(self.mutate(f), "evil.example")

    def test_oauth_profile_fails(self):
        self.assertFails(self.mutate(lambda p: p.update(AllowedOAuthFlows=["code", "implicit"])), "AllowedOAuthFlows")
        self.assertFails(self.mutate(lambda p: p.update(AllowedOAuthFlowsUserPoolClient=False)), "AllowedOAuthFlowsUserPoolClient")
        self.assertFails(self.mutate(lambda p: p.update(SupportedIdentityProviders=["COGNITO", "Google"])), "SupportedIdentityProviders")
        self.assertFails(self.mutate(lambda p: p["AllowedOAuthScopes"].append("aws.cognito.signin.user.admin")), "AllowedOAuthScopes")
        self.assertFails(self.mutate(lambda p: p.update(EnableTokenRevocation=False)), "EnableTokenRevocation")

    def test_missing_resource_fails(self):
        self.assertFails(c.check_doc({"Resources": {}}), "SignInClient is missing")


if __name__ == "__main__":
    unittest.main()
