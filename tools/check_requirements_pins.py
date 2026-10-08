#!/usr/bin/env python3
"""Requirements pin guard (ENC-TSK-Q42 / ENC-ISS-835).

Fails when a backend/lambda/*/requirements.txt has (a) a bare unversioned
requirement line (e.g. ``certifi``) or (b) an ``mcp`` requirement without an
exact ``==`` pin. Range specifiers (``>=x,<y``, ``>=x``) are allowed.
Comments, blank lines, ``-r``/``-c``/option lines and URL/VCS lines are ignored.
"""
from __future__ import annotations

import glob
import re
import sys
from typing import List

_NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$")


def check_text(text: str, label: str = "requirements.txt") -> List[str]:
    errors: List[str] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #", 1)[0].split(";", 1)[0].strip()
        if not line or line.startswith(("#", "-")) or "://" in line or "@" in line:
            continue
        m = _NAME_RE.match(line)
        if not m:
            continue
        name, spec = m.group(1).lower().replace("_", "-"), m.group(3).strip()
        if not spec:
            errors.append(f"{label}:{lineno}: bare unversioned requirement '{line}'")
        elif name == "mcp" and not re.search(r"(?<![<>!~=])==\s*\d", spec):
            errors.append(f"{label}:{lineno}: 'mcp' must have an exact == pin, got '{line}'")
    return errors


def main(argv: List[str]) -> int:
    paths = argv or sorted(glob.glob("backend/lambda/*/requirements.txt"))
    errors: List[str] = []
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            errors.extend(check_text(fh.read(), path))
    for e in errors:
        print(f"[ERROR] {e}")
    print(f"[{'ERROR' if errors else 'SUCCESS'}] checked {len(paths)} files, {len(errors)} violation(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
