import importlib.util
import pathlib
import sys

MODULE_PATH = pathlib.Path(__file__).with_name("pwa_cognito_evidence_capture.py")
SPEC = importlib.util.spec_from_file_location("pwa_cognito_capture", MODULE_PATH)
mod = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = mod
SPEC.loader.exec_module(mod)


def test_extract_session_payload_from_wrapped_response():
    raw = {
        "success": True,
        "session": {
            "target_origin": "https://jreese.net",
            "playwright_cookies": [
                {
                    "name": "enceladus_id_token",
                    "value": "abc.def.ghi",
                    "url": "https://jreese.net",
                    "path": "/",
                    "secure": True,
                    "httpOnly": True,
                    "sameSite": "None",
                }
            ],
        },
    }
    parsed = mod._extract_session_payload(raw)
    assert parsed.target_origin == "https://jreese.net"
    assert len(parsed.playwright_cookies) == 1
    assert parsed.playwright_cookies[0]["name"] == "enceladus_id_token"


def test_normalize_routes_accepts_relative_and_absolute_same_origin():
    routes = mod._normalize_routes(
        ["/enceladus/", "https://jreese.net/enceladus/terminal/manage"],
        "https://jreese.net",
    )
    assert routes[0][0] == "/enceladus/"
    assert routes[0][1] == "https://jreese.net/enceladus/"
    assert routes[1][0] == "/enceladus/terminal/manage"


def test_normalize_routes_rejects_cross_origin():
    try:
        mod._normalize_routes(["https://example.com/enceladus/"], "https://jreese.net")
    except mod.EvidenceCaptureError as exc:
        assert "origin mismatch" in str(exc)
        return
    raise AssertionError("expected EvidenceCaptureError for cross-origin route")


def test_redact_text_masks_jwt_and_cookie_token():
    value = "enceladus_id_token=abc.def.ghi; Authorization: Bearer secret-token-123"
    redacted = mod._redact_text(value)
    assert "abc.def.ghi" not in redacted
    assert "secret-token-123" not in redacted
    assert "[REDACTED_TOKEN]" in redacted


def test_redact_url_masks_sensitive_query_params():
    redacted = mod._redact_url(
        "https://jreese.net/enceladus/callback?code=top-secret&foo=ok&id_token=a.b.c"
    )
    assert "top-secret" not in redacted
    assert "a.b.c" not in redacted
    assert "foo=ok" in redacted
