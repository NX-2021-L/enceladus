"""Tests for tools/escalation_redrive_sweep.py (ENC-TSK-P89 AC-3).

Stubs urllib.request.urlopen so no real network call happens. Covers:
  - dry-run filters out escalations that already have applied_at set
  - dry-run never POSTs
  - --apply POSTs to the idempotent apply endpoint for each remaining id
  - missing API key env var exits 2 and never makes a request
  - the list call carries no status filter (client-side filtering instead)
  - status=failed + applied_at unset is a candidate; applied/denied/requested
    are excluded
"""
import importlib.util
import json
import pathlib
import sys
from unittest import mock

MODULE_PATH = pathlib.Path(__file__).with_name("escalation_redrive_sweep.py")
SPEC = importlib.util.spec_from_file_location("escalation_redrive_sweep", MODULE_PATH)
sweep = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = sweep
SPEC.loader.exec_module(sweep)


class _FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self._status = status

    def read(self):
        return json.dumps(self._payload).encode("utf-8")

    def getcode(self):
        return self._status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _list_payload(items, next_cursor=None):
    payload = {"success": True, "escalations": items, "count": len(items)}
    if next_cursor:
        payload["next_cursor"] = next_cursor
    return payload


def _esc(esc_id, applied_at=None, target="ENC-TSK-J10", status="approved"):
    item = {"item_id": esc_id, "status": status, "target_record_id": target,
            "mutation_type": "direct_state_override", "decided_at": "2026-09-16T00:00:00Z"}
    if applied_at:
        item["applied_at"] = applied_at
    return item


def test_missing_api_key_exits_2(monkeypatch, capsys):
    monkeypatch.delenv(sweep.ENV_KEY_NAME, raising=False)
    with mock.patch("urllib.request.urlopen") as urlopen:
        sys.argv = ["escalation_redrive_sweep.py", "--base-url", "https://x/api/v1/tracker"]
        code = None
        try:
            sweep.main()
        except SystemExit as exc:
            code = exc.code
        assert code == 2
        urlopen.assert_not_called()
    captured = capsys.readouterr()
    assert sweep.ENV_KEY_NAME in captured.err


def test_dry_run_filters_applied_and_never_posts(monkeypatch, capsys):
    monkeypatch.setenv(sweep.ENV_KEY_NAME, "test-key-value")
    items = [_esc("ENC-ESC-105"), _esc("ENC-ESC-106", applied_at="2026-09-01T00:00:00Z")]

    with mock.patch("urllib.request.urlopen", return_value=_FakeResponse(_list_payload(items))) as urlopen:
        sys.argv = ["escalation_redrive_sweep.py", "--base-url", "https://enceladus-gamma.jreese.net/api/v1/tracker"]
        code = sweep.main()

    assert code == 0
    assert urlopen.call_count == 1  # only the list call, no apply POSTs
    out = capsys.readouterr().out
    assert "ENC-ESC-105" in out
    assert "ENC-ESC-106" not in out
    assert "Dry-run only" in out
    assert "test-key-value" not in out


def test_apply_posts_for_each_unapplied_id(monkeypatch, capsys):
    monkeypatch.setenv(sweep.ENV_KEY_NAME, "test-key-value")
    items = [_esc("ENC-ESC-105"), _esc("ENC-ESC-107")]
    responses = [
        _FakeResponse(_list_payload(items)),
        _FakeResponse({"success": True, "result": {"after": {"status": "deploy-success"}}}),
        _FakeResponse({"success": True, "result": {"after": {"status": "closed"}}}),
    ]

    with mock.patch("urllib.request.urlopen", side_effect=responses) as urlopen:
        sys.argv = [
            "escalation_redrive_sweep.py",
            "--base-url", "https://enceladus-gamma.jreese.net/api/v1/tracker",
            "--apply",
        ]
        code = sweep.main()

    assert code == 0
    assert urlopen.call_count == 3  # 1 list + 2 apply POSTs
    apply_requests = [call.args[0] for call in urlopen.call_args_list[1:]]
    for req in apply_requests:
        assert req.get_method() == "POST"
        assert req.full_url.endswith("/apply")
    out = capsys.readouterr().out
    assert "HTTP 200" in out


def test_list_call_has_no_status_filter(monkeypatch):
    # ENC-TSK-P89: filtering moved client-side so both approved and failed
    # candidates are caught in one pass.
    monkeypatch.setenv(sweep.ENV_KEY_NAME, "test-key-value")
    with mock.patch("urllib.request.urlopen",
                    return_value=_FakeResponse(_list_payload([]))) as urlopen:
        sys.argv = ["escalation_redrive_sweep.py", "--base-url", "https://x/api/v1/tracker"]
        sweep.main()
    requested_url = urlopen.call_args_list[0].args[0].full_url
    assert "status=" not in requested_url
    assert "page_size=200" in requested_url


def test_dry_run_shows_failed_unapplied_and_excludes_applied_denied_requested(monkeypatch, capsys):
    monkeypatch.setenv(sweep.ENV_KEY_NAME, "test-key-value")
    items = [
        _esc("ENC-ESC-105", status="failed"),
        _esc("ENC-ESC-106", status="applied", applied_at="2026-09-01T00:00:00Z"),
        _esc("ENC-ESC-108", status="denied"),
        _esc("ENC-ESC-109", status="requested"),
    ]

    with mock.patch("urllib.request.urlopen", return_value=_FakeResponse(_list_payload(items))) as urlopen:
        sys.argv = ["escalation_redrive_sweep.py", "--base-url", "https://enceladus-gamma.jreese.net/api/v1/tracker"]
        code = sweep.main()

    assert code == 0
    assert urlopen.call_count == 1  # only the list call, no apply POSTs
    out = capsys.readouterr().out
    assert "ENC-ESC-105" in out
    assert "status=failed" in out
    for excluded in ("ENC-ESC-106", "ENC-ESC-108", "ENC-ESC-109"):
        assert excluded not in out
    assert "Dry-run only" in out


def test_apply_posts_for_failed_unapplied_id(monkeypatch, capsys):
    monkeypatch.setenv(sweep.ENV_KEY_NAME, "test-key-value")
    items = [_esc("ENC-ESC-105", status="failed")]
    responses = [
        _FakeResponse(_list_payload(items)),
        _FakeResponse({"success": True, "status": "applied", "result": {"after": {"status": "closed"}}}),
    ]

    with mock.patch("urllib.request.urlopen", side_effect=responses) as urlopen:
        sys.argv = [
            "escalation_redrive_sweep.py",
            "--base-url", "https://enceladus-gamma.jreese.net/api/v1/tracker",
            "--apply",
        ]
        code = sweep.main()

    assert code == 0
    assert urlopen.call_count == 2  # 1 list + 1 apply POST
    apply_req = urlopen.call_args_list[1].args[0]
    assert apply_req.get_method() == "POST"
    assert apply_req.full_url.endswith("/ENC-ESC-105/apply")
    out = capsys.readouterr().out
    assert "HTTP 200" in out


def test_walks_next_cursor_bounded(monkeypatch):
    monkeypatch.setenv(sweep.ENV_KEY_NAME, "test-key-value")
    page1 = _FakeResponse(_list_payload([_esc("ENC-ESC-001")], next_cursor="cur1"))
    page2 = _FakeResponse(_list_payload([_esc("ENC-ESC-002")]))

    with mock.patch("urllib.request.urlopen", side_effect=[page1, page2]) as urlopen:
        sys.argv = ["escalation_redrive_sweep.py", "--base-url", "https://x/api/v1/tracker"]
        code = sweep.main()

    assert code == 0
    assert urlopen.call_count == 2
    second_url = urlopen.call_args_list[1].args[0].full_url
    assert "next_cursor=cur1" in second_url
