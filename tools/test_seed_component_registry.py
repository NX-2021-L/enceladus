#!/usr/bin/env python3
"""Unit tests for tools/seed-component-registry.py.

ENC-TSK-M10 / ENC-ISS-507: the seed script used to default
--direct-apigw-base/COORDINATION_DIRECT_APIGW_BASE to prod's API Gateway URL.
An assistant-key run intended for gamma that forgot to pass the flag silently
misrouted its component writes to prod. These tests pin the new behavior:
resolve_direct_apigw_base() has no hardcoded default and fails loud when an
assistant key is in use for a real (non-dry-run) write.
"""
import importlib.util
import pathlib

import pytest

# The module filename contains a hyphen, so load it by path rather than import.
_MODULE_PATH = pathlib.Path(__file__).with_name("seed-component-registry.py")
_spec = importlib.util.spec_from_file_location("seed_component_registry", _MODULE_PATH)
seed_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(seed_mod)

resolve_direct_apigw_base = seed_mod.resolve_direct_apigw_base

# The stale prod default that ENC-ISS-507 removed; no resolution path may return it.
_PROD_APIGW_HOST = "8nkzqkmxqc.execute-api"


def test_explicit_flag_wins_and_is_normalized():
    # Explicit flag is honored and trailing slash / whitespace stripped.
    result = resolve_direct_apigw_base(
        "  https://gamma.example/api/v1/coordination/  ",
        env_value="https://env.example/api",
        assistant_key="k",
        dry_run=False,
    )
    assert result == "https://gamma.example/api/v1/coordination"


def test_env_var_used_when_flag_absent():
    result = resolve_direct_apigw_base(
        None,
        env_value="https://env.example/api/v1/coordination",
        assistant_key="k",
        dry_run=False,
    )
    assert result == "https://env.example/api/v1/coordination"


def test_flag_precedence_over_env():
    result = resolve_direct_apigw_base(
        "https://flag.example/api",
        env_value="https://env.example/api",
        assistant_key="k",
        dry_run=False,
    )
    assert result == "https://flag.example/api"


def test_assistant_key_without_base_fails_loud():
    # The core ENC-ISS-507 guard: no base + assistant key + real write -> raise.
    with pytest.raises(ValueError) as excinfo:
        resolve_direct_apigw_base(None, env_value="", assistant_key="secret", dry_run=False)
    assert "ENC-ISS-507" in str(excinfo.value)


def test_dry_run_is_exempt_from_guard():
    # Dry runs make no request, so a missing base must not raise.
    result = resolve_direct_apigw_base(None, env_value="", assistant_key="secret", dry_run=True)
    assert result == ""


def test_no_assistant_key_returns_empty_never_prod_default():
    # Without an assistant key there is no direct-APIGW requirement, and crucially
    # no silent prod default is ever produced (that was the ENC-ISS-507 misroute).
    result = resolve_direct_apigw_base(None, env_value="", assistant_key="", dry_run=False)
    assert result == ""
    assert _PROD_APIGW_HOST not in result


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
