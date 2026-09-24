"""Minimal internal HTTP helper for governed read surfaces."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional
from urllib import error, request
from urllib.parse import urlencode

from config import internal_headers

_TIMEOUT = 25


def get_json(url: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if params:
        url = f"{url}?{urlencode(params)}"
    req = request.Request(url, method="GET", headers=internal_headers())
    with request.urlopen(req, timeout=_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def post_json(url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    headers = internal_headers()
    req = request.Request(url, data=body, method="POST", headers=headers)
    try:
        with request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} from {url}: {detail}") from exc
