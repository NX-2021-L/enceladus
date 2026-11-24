#!/usr/bin/env python3
"""ENC-TSK-S57 / MCP fleet F-12: static profile guard for the MCP sign-in client.

The Cognito app client in infrastructure/cloudformation/13-mcp-signin-client.yaml is the one fixed public client of
the kit sign-in service. A pull request must not be able to weaken it: no password / user-auth / custom flows, no
secret, authorization-code flow only, callbacks only on the service's own hosts. Self-contained: reads the template
from the working tree, no network, no AWS credentials, no dependency beyond PyYAML.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, List

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = REPO_ROOT / "infrastructure" / "cloudformation" / "13-mcp-signin-client.yaml"
RESOURCE = "SignInClient"
RESOURCE_TYPE = "AWS::Cognito::UserPoolClient"

REQUIRED_AUTH_FLOWS = ["ALLOW_REFRESH_TOKEN_AUTH"]
FORBIDDEN_AUTH_FLOWS = [
    "ALLOW_USER_AUTH",
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_ADMIN_USER_PASSWORD_AUTH",
    "ALLOW_CUSTOM_AUTH",
]
ALLOWED_SCOPES = {"openid", "email", "profile"}
ALLOWED_CALLBACKS = {
    "https://mcp.jreese.net/callback",
    "https://mcp-gamma.jreese.net/callback",
}


class _Loader(yaml.SafeLoader):
    """SafeLoader that keeps CloudFormation short-form tags as {"Fn::X": value} (Ref stays "Ref")."""


def _tag(loader: yaml.Loader, suffix: str, node: yaml.Node) -> dict:
    if isinstance(node, yaml.ScalarNode):
        value: Any = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)
    return {("Ref" if suffix == "Ref" else f"Fn::{suffix}"): value}


_Loader.add_multi_constructor("!", _tag)


def _callback_leaves(value: Any) -> List[Any]:
    """Flatten a CallbackURLs entry: both branches of an Fn::If are checked; anything else is one leaf."""
    if isinstance(value, dict) and set(value) == {"Fn::If"}:
        args = value["Fn::If"]
        if isinstance(args, list) and len(args) == 3:
            return _callback_leaves(args[1]) + _callback_leaves(args[2])
    return [value]


def check_doc(doc: Any) -> List[str]:
    errors: List[str] = []
    res = (doc or {}).get("Resources", {}).get(RESOURCE) if isinstance(doc, dict) else None
    if not isinstance(res, dict):
        return [f"Resources.{RESOURCE} is missing"]
    if res.get("Type") != RESOURCE_TYPE:
        errors.append(f"Resources.{RESOURCE}.Type must be {RESOURCE_TYPE}, found {res.get('Type')!r}")
    props = res.get("Properties")
    if not isinstance(props, dict):
        return errors + [f"Resources.{RESOURCE}.Properties is missing"]

    flows = props.get("ExplicitAuthFlows")
    if flows != REQUIRED_AUTH_FLOWS:
        errors.append(f"ExplicitAuthFlows must be exactly {REQUIRED_AUTH_FLOWS}, found {flows!r}")
    for bad in FORBIDDEN_AUTH_FLOWS:
        if isinstance(flows, list) and bad in flows:
            errors.append(f"ExplicitAuthFlows must not contain {bad}")

    if props.get("GenerateSecret") is not False:
        errors.append(f"GenerateSecret must be false (public client), found {props.get('GenerateSecret')!r}")
    if props.get("AllowedOAuthFlows") != ["code"]:
        errors.append(f"AllowedOAuthFlows must be exactly ['code'], found {props.get('AllowedOAuthFlows')!r}")
    if props.get("AllowedOAuthFlowsUserPoolClient") is not True:
        errors.append(
            "AllowedOAuthFlowsUserPoolClient must be true, found "
            f"{props.get('AllowedOAuthFlowsUserPoolClient')!r}"
        )
    if props.get("SupportedIdentityProviders") != ["COGNITO"]:
        errors.append(
            f"SupportedIdentityProviders must be exactly ['COGNITO'], found {props.get('SupportedIdentityProviders')!r}"
        )

    scopes = props.get("AllowedOAuthScopes")
    if not isinstance(scopes, list) or not scopes:
        errors.append(f"AllowedOAuthScopes must be a non-empty list, found {scopes!r}")
    else:
        extra = [s for s in scopes if s not in ALLOWED_SCOPES]
        if extra:
            errors.append(f"AllowedOAuthScopes has scopes outside {sorted(ALLOWED_SCOPES)}: {extra}")

    callbacks = props.get("CallbackURLs")
    if not isinstance(callbacks, list) or not callbacks:
        errors.append(f"CallbackURLs must be a non-empty list, found {callbacks!r}")
    else:
        for entry in callbacks:
            for leaf in _callback_leaves(entry):
                if not isinstance(leaf, str) or leaf not in ALLOWED_CALLBACKS:
                    errors.append(
                        f"CallbackURLs entry {leaf!r} is not one of the service's own callbacks "
                        f"{sorted(ALLOWED_CALLBACKS)}"
                    )

    if props.get("EnableTokenRevocation") is not True:
        errors.append(f"EnableTokenRevocation must be true, found {props.get('EnableTokenRevocation')!r}")
    return errors


def check(path: Path | str = TEMPLATE) -> List[str]:
    with open(path, encoding="utf-8") as fh:
        doc = yaml.load(fh, Loader=_Loader)
    return check_doc(doc)


def main() -> int:
    errors = check()
    for e in errors:
        print(f"FAIL: {e}")
    if not errors:
        print("ok: MCP sign-in client profile holds (F-12)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
