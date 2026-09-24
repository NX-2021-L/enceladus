"""Unit tests for the ENC-TSK-L05 AC-1 hardening-fields backfill.

Covers tools/seed-component-registry.py's KNOWN_COMPONENTS (the five
ENC-TSK-E68 fields on active enceladus-project entries) and the sibling
verifier tools/verify_component_hardening_fields.py.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys

MODULE_DIR = pathlib.Path(__file__).parent

_HARDENING_FIELDS = (
    "required_iam_actions",
    "required_env_secrets",
    "required_apigw_routes",
    "required_cfn_resources",
    "required_lambda_env_vars",
)


def _load_module(filename: str, module_name: str):
    path = MODULE_DIR / filename
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _load_seed():
    return _load_module("seed-component-registry.py", "enceladus_seed_component_registry_under_test")


def _active_enceladus_components(seed_module):
    return [
        c
        for c in seed_module.KNOWN_COMPONENTS
        if c.get("project_id") == "enceladus" and c.get("status") == "active"
    ]


def test_all_active_enceladus_components_declare_all_five_hardening_fields():
    seed = _load_seed()
    components = _active_enceladus_components(seed)
    assert len(components) == 23, (
        "Expected 23 active enceladus-project components after ENC-TSK-L05 "
        "AC2-6 (v3 hardening). ENC-TSK-L06 added comp-id-service; AC-2 split "
        "the former single comp-enceladus-pwa into comp-enceladus-pwa-frontend, "
        "comp-enceladus-pwa-cdn, and comp-enceladus-api-gateway; AC-3 added "
        "comp-enceladus-neo4j; AC-4 added nine comp-enceladus-cfn-* umbrellas; "
        "AC-6 added comp-umbrella-governance-documentation. "
        "If this fails because a new component was added, extend this test's "
        "expectations rather than deleting the assertion."
    )
    for comp in components:
        cid = comp["component_id"]
        for field in _HARDENING_FIELDS:
            assert field in comp, f"{cid} is missing '{field}'"
            assert isinstance(comp[field], list), f"{cid}.{field} must be a list"
            assert all(isinstance(v, str) for v in comp[field]), (
                f"{cid}.{field} must be a list of strings"
            )


def test_non_enceladus_components_are_untouched_by_this_backfill():
    """AC-1 scope is enceladus-project active components only; this backfill
    must not have added the hardening fields to other projects' entries."""
    seed = _load_seed()
    other_project_components = [
        c for c in seed.KNOWN_COMPONENTS if c.get("project_id") != "enceladus"
    ]
    assert other_project_components, "sanity check: seed file should still have non-enceladus entries"
    for comp in other_project_components:
        for field in _HARDENING_FIELDS:
            assert field not in comp, (
                f"{comp['component_id']} (project={comp.get('project_id')}) "
                f"unexpectedly has '{field}' -- ENC-TSK-L05 AC-1 scope is "
                "enceladus-project components only"
            )


def test_lambda_components_have_nonempty_iam_actions_or_documented_reason():
    """Every Lambda-category component either has a non-empty
    required_iam_actions list, or is comp-checkout-service (whose role is
    deliberately out-of-band / not CFN-managed, documented inline in the seed
    file) -- an empty list must never be silently unconsidered."""
    seed = _load_seed()
    components = _active_enceladus_components(seed)
    lambda_components = [c for c in components if c.get("category") == "lambda"]
    assert len(lambda_components) == 6
    for comp in lambda_components:
        cid = comp["component_id"]
        actions = comp["required_iam_actions"]
        if cid == "comp-checkout-service":
            # Out-of-band role; code-derived actions still populated (non-empty).
            assert actions, f"{cid} should have code-derived IAM actions even though its role isn't CFN-managed"
        else:
            assert actions, f"{cid} (CFN-managed role) should have a non-empty required_iam_actions list"


def test_apigw_routes_empty_for_non_http_lambdas():
    """comp-lifecycle-service, comp-scoring-service, and comp-id-service (ENC-TSK-L06)
    are invoked synchronously / via SNS / via direct Lambda invoke respectively, never
    over HTTP -- their required_apigw_routes must be empty, and non-empty for the three
    that do serve routes."""
    seed = _load_seed()
    by_id = {c["component_id"]: c for c in _active_enceladus_components(seed)}

    assert by_id["comp-lifecycle-service"]["required_apigw_routes"] == []
    assert by_id["comp-scoring-service"]["required_apigw_routes"] == []
    assert by_id["comp-id-service"]["required_apigw_routes"] == []

    for cid in ("comp-checkout-service", "comp-coordination-api", "comp-tracker-mutation"):
        assert by_id[cid]["required_apigw_routes"], f"{cid} should have non-empty required_apigw_routes"


def test_required_transition_type_untouched():
    """This backfill must not have disturbed the pre-existing F50
    required_transition_type field on any entry."""
    seed = _load_seed()
    for comp in seed.KNOWN_COMPONENTS:
        assert "required_transition_type" in comp, (
            f"{comp['component_id']} lost its required_transition_type field"
        )


def test_verify_script_passes_against_current_seed_manifest():
    """tools/verify_component_hardening_fields.py's seed-manifest audit
    (no live probe) should exit 0 against the current KNOWN_COMPONENTS."""
    verify = _load_module("verify_component_hardening_fields.py", "enceladus_verify_hardening_fields_under_test")
    components = verify._load_seed_components()
    failures, audited = verify._audit_seed(components)
    assert audited == 23
    assert failures == []


# ── ENC-TSK-L05 AC2-6: v3 identity-field tests ───────────────────────────────

_V3_IDENTITY_FIELDS = (
    "component_address",
    "component_repo_dir",
    "component_address_class",
    "component_class",
)

_VALID_ADDRESS_CLASSES = {
    "aws_arn",
    "https_url",
    "cloudflare_resource",
    "neo4j_auradb",
    "external_manifest",
    "meta",
}

_VALID_COMPONENT_CLASSES = {"physical", "external", "meta"}

_VALID_REQUIRED_TRANSITION_TYPES = {"code", "external_deploy", "documentation"}


def test_all_active_enceladus_components_have_valid_v3_identity_fields():
    """(a) Every active enceladus seed component declares the four v3 identity
    fields as non-empty strings with valid enum values, and a v3
    required_transition_type."""
    seed = _load_seed()
    components = _active_enceladus_components(seed)
    assert components, "sanity: expected active enceladus components"
    for comp in components:
        cid = comp["component_id"]
        for field in _V3_IDENTITY_FIELDS:
            assert field in comp, f"{cid} is missing v3 field '{field}'"
            assert isinstance(comp[field], str), f"{cid}.{field} must be a str"
            assert comp[field].strip(), f"{cid}.{field} must be non-empty"
        assert comp["component_address_class"] in _VALID_ADDRESS_CLASSES, (
            f"{cid}.component_address_class={comp['component_address_class']!r} "
            f"not in {sorted(_VALID_ADDRESS_CLASSES)}"
        )
        assert comp["component_class"] in _VALID_COMPONENT_CLASSES, (
            f"{cid}.component_class={comp['component_class']!r} "
            f"not in {sorted(_VALID_COMPONENT_CLASSES)}"
        )


def test_required_transition_type_is_v3_value_for_enceladus_components():
    """(c) required_transition_type is always a v3 value for active enceladus
    components (code / external_deploy / documentation)."""
    seed = _load_seed()
    for comp in _active_enceladus_components(seed):
        rtt = comp.get("required_transition_type")
        assert rtt in _VALID_REQUIRED_TRANSITION_TYPES, (
            f"{comp['component_id']}.required_transition_type={rtt!r} "
            f"is not a v3 value ({sorted(_VALID_REQUIRED_TRANSITION_TYPES)})"
        )


def test_component_address_is_unique_across_active_enceladus_components():
    """(b) MECE — no two active enceladus components share a
    component_address."""
    seed = _load_seed()
    addrs = [c["component_address"] for c in _active_enceladus_components(seed)]
    dupes = sorted({a for a in addrs if addrs.count(a) > 1})
    assert not dupes, f"duplicate component_address values: {dupes}"


def test_component_repo_dir_is_an_antichain_for_non_meta_components():
    """(b) MECE — component_repo_dir values (excluding meta: sentinels) form an
    antichain: none is a path-prefix of another."""
    seed = _load_seed()
    dirs = [
        (c["component_id"], c["component_repo_dir"])
        for c in _active_enceladus_components(seed)
        if not c["component_repo_dir"].startswith("meta:")
    ]
    for cid_a, dir_a in dirs:
        for cid_b, dir_b in dirs:
            if cid_a == cid_b or dir_a == dir_b:
                continue
            assert not (dir_a + "/").startswith(dir_b + "/"), (
                f"{dir_a!r} ({cid_a}) is nested under {dir_b!r} ({cid_b}); "
                "component_repo_dir values must form an antichain"
            )


def test_meta_repo_dir_sentinels_are_unique():
    """(b) MECE — meta: repo-dir sentinels are exempt from the prefix check but
    must still be unique."""
    seed = _load_seed()
    meta_dirs = [
        c["component_repo_dir"]
        for c in _active_enceladus_components(seed)
        if c["component_repo_dir"].startswith("meta:")
    ]
    assert len(meta_dirs) == len(set(meta_dirs)), (
        f"meta: component_repo_dir sentinels must be unique: {meta_dirs}"
    )


def test_verify_script_v3_identity_audit_passes_against_current_seed():
    """The v3 identity audit in verify_component_hardening_fields.py should
    pass (no failures) against the current KNOWN_COMPONENTS."""
    verify = _load_module(
        "verify_component_hardening_fields.py",
        "enceladus_verify_hardening_fields_v3_under_test",
    )
    components = verify._load_seed_components()
    failures, audited = verify._audit_v3_identity(components)
    assert audited == 23
    assert failures == [], f"v3 identity audit failures: {failures}"
