"""ELR context landing zone (ENC-TSK-Q50, ENC-FTR-147 / DOC-412AB7081565 FR-4, FR-5).

``elr compact_context`` lands every section it fetches on disk so the inline
digest can stay small:

    ~/.enceladus/context/<run_id>/<section>.json      one file per section
    ~/.enceladus/context/<run_id>/<run_id>.ids        ranked ids, one per line

The ids file is in exactly the format ``elr_batch_get --ids-file`` consumes
(one item id per line; never raw sort keys). It lives INSIDE the run
directory so that pruning a run removes it too and so a later read-through
join (ENC-TSK-Q52) can recognise it by its parent directory.

The root defaults to ``~/.enceladus/context``; ``ELR_CONTEXT_DIR`` (env) or an
explicit ``root`` argument (the verb's ``--out-dir``) overrides it so tests
never touch the real home directory. Standard library only.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any, Iterable, Optional, Tuple

DEFAULT_CONTEXT_DIR = "~/.enceladus/context"
CONTEXT_DIR_ENV = "ELR_CONTEXT_DIR"

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def context_root(override: Optional[str] = None) -> Path:
    """Resolve the context root: explicit override, then env, then default."""
    raw = (override or "").strip() or os.environ.get(CONTEXT_DIR_ENV, "").strip() or DEFAULT_CONTEXT_DIR
    return Path(raw).expanduser()


def new_ulid(now_ms: Optional[int] = None) -> str:
    """A 26-character ULID: 48-bit millisecond timestamp + 80 random bits,
    Crockford base32. Lexicographic order == creation order (the pruning
    code relies on neither; it reads mtimes)."""
    ts = int(time.time() * 1000) if now_ms is None else int(now_ms)
    value = (ts << 80) | secrets.randbits(80)
    chars = []
    for _ in range(26):
        chars.append(_CROCKFORD[value & 31])
        value >>= 5
    return "".join(reversed(chars))


def run_dir(root: Path, run_id: str) -> Path:
    return root / run_id


def serialize_section(body: Any) -> bytes:
    """Section bodies are written verbatim (never truncated), as UTF-8 JSON."""
    return json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def write_section(directory: Path, name: str, body: Any) -> Tuple[int, str]:
    """Write ``<directory>/<name>.json``; return (byte size, sha256 hex)."""
    directory.mkdir(parents=True, exist_ok=True)
    data = serialize_section(body)
    (directory / f"{name}.json").write_bytes(data)
    return len(data), hashlib.sha256(data).hexdigest()


def ids_file_path(directory: Path, run_id: str) -> Path:
    return directory / f"{run_id}.ids"


def write_ids_file(directory: Path, run_id: str, ids: Iterable[str]) -> Path:
    """One id per line -- the ``elr_batch_get --ids-file`` format."""
    directory.mkdir(parents=True, exist_ok=True)
    path = ids_file_path(directory, run_id)
    path.write_text("".join(f"{i}\n" for i in ids), encoding="utf-8")
    return path
