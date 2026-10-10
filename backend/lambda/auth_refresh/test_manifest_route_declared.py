"""DVP-TSK-861: the manifest route auth_refresh serves must be declared on the
HTTP API (03-api.yaml uses explicit route keys; an undeclared path 404s)."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def test_manifest_route_key_targets_auth_refresh():
    api = (ROOT / "infrastructure/cloudformation/03-api.yaml").read_text()
    m = re.search(r"RouteKey: GET /api/v1/auth/manifest\n\s+Target: !Sub integrations/\$\{(\w+)\}", api)
    assert m, "GET /api/v1/auth/manifest route key missing from 03-api.yaml"
    assert m.group(1) == "AuthRefreshIntegration"
