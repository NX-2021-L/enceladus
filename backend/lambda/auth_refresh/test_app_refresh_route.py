"""DVP-TSK-B42: GET /api/v1/app/refresh, the server half of the PWA's App refresh.

The route answers 200 with Clear-Site-Data for cache, storage and
executionContexts (never cookies: io stays signed in), no-store, a tiny JSON
body, and logs exactly one identifier-free line. It must be declared on the
HTTP API and wired to the auth-refresh integration.
"""
import importlib.util
import json
import logging
import pathlib
import re
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "shared_layer" / "python"))
sys.path.insert(0, str(HERE.parent / "shared_layer"))
spec = importlib.util.spec_from_file_location("auth_refresh_lf_app_refresh", HERE / "lambda_function.py")
lf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lf)

ROOT = HERE.parents[2]


def _event(headers=None, method="GET", path="/api/v1/app/refresh"):
    return {
        "requestContext": {"http": {"method": method, "path": path}},
        "headers": headers or {},
        "cookies": ["enceladus_refresh_token=RT.synthetic", "enceladus_id_token=ID.synthetic"],
    }


def test_headers_are_exactly_clear_site_data_no_store_and_json():
    r = lf.lambda_handler(_event(), None)
    assert r["statusCode"] == 200
    assert r["headers"] == {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "Clear-Site-Data": '"cache", "storage", "executionContexts"',
    }
    assert json.loads(r["body"]) == {"refreshed": True}


def test_clear_site_data_never_wipes_cookies_and_sets_no_cookie():
    r = lf.lambda_handler(_event(), None)
    assert "cookies" not in r["headers"].get("Clear-Site-Data", "").lower()
    assert "cookies" not in r  # nothing set or cleared: the session survives
    assert not any(k.lower() == "set-cookie" for k in r["headers"])


def test_logs_one_identifier_free_line(caplog):
    caplog.set_level(logging.DEBUG)
    lf.lambda_handler(_event({"origin": "https://enceladus.jreese.net", "user-agent": "UA/1"}), None)
    msgs = [rec.getMessage() for rec in caplog.records]
    assert msgs == ['{"event":"app_refresh"}']
    assert "RT.synthetic" not in caplog.text and "ID.synthetic" not in caplog.text


@pytest.mark.parametrize("site", ["same-origin", "none", "SAME-ORIGIN", None])
def test_same_origin_navigations_and_unlabelled_clients_are_served(site):
    headers = {"Sec-Fetch-Site": site} if site is not None else {}
    assert lf.lambda_handler(_event(headers), None)["statusCode"] == 200


@pytest.mark.parametrize("site", ["cross-site", "same-site"])
def test_cross_site_loads_cannot_make_a_browser_wipe_its_storage(site, caplog):
    caplog.set_level(logging.DEBUG)
    r = lf.lambda_handler(_event({"sec-fetch-site": site}), None)
    assert r["statusCode"] == 403
    assert not any(k.lower() == "clear-site-data" for k in r["headers"])
    assert "app_refresh" not in caplog.text


def test_only_get_is_served():
    assert lf.lambda_handler(_event(method="POST"), None)["statusCode"] in (401, 405)
    assert lf.lambda_handler(_event(method="POST"), None)["headers"].get("Clear-Site-Data") is None


def test_route_is_declared_on_the_http_api_and_wired_to_auth_refresh():
    api = (ROOT / "infrastructure" / "cloudformation" / "03-api.yaml").read_text()
    m = re.search(r"  RouteAppRefresh:\n    Type: AWS::ApiGatewayV2::Route\n    Properties:\n(.*?)\n\n", api, re.S)
    assert m, "RouteAppRefresh missing from 03-api.yaml"
    assert "RouteKey: GET /api/v1/app/refresh" in m.group(1)
    assert "Target: !Sub integrations/${AuthRefreshIntegration}" in m.group(1)
