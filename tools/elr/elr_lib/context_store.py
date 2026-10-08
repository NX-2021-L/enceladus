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


# ---------------------------------------------------------------------------
# Retention (ENC-TSK-Q52, FR-11 / M-7)
# ---------------------------------------------------------------------------

# B_session: the F11 fixed point (DOC-C6584044BEEB Definition 5), 40.2 MB with
# the decimal megabyte the BRD's M-7 arithmetic uses (40.2 MB / 152 KB per
# record-mode run = 264 runs before pruning). This is THE one place the
# constant lives; elr_compact_context and every test import it from here.
F11_B_SESSION_MB = 40.2
F11_B_SESSION_BYTES = int(F11_B_SESSION_MB * 1_000_000)
# A run older than this is pruned regardless of the byte cap (matches the
# digest side-file staleness rule, elr_lib.manifest.STALE_AFTER_HOURS).
RUN_MAX_AGE_SECONDS = 24 * 3600

LEDGER_FILENAME = "ledger.jsonl"
LEDGER_MODE = 0o600
LEDGER_STRING_MAX = 64
# The server-echoed intent signature is a sha256 label, not a title; it is the
# join key of the ledger, so it is stored verbatim and is the one exemption
# from the 64-character rule.
LEDGER_LONG_STRING_KEYS = frozenset({"intent_signature"})
_LEDGER_FORBIDDEN_KEYS = frozenset(
    {"title", "titles", "body", "content", "key", "api_key", "token", "secret", "password", "authorization", "query", "summary"}
)


def _dir_bytes(directory: Path) -> int:
    total = 0
    for path in directory.rglob("*"):
        try:
            if path.is_file():
                total += path.stat().st_size
        except OSError:
            continue
    return total


def _run_dirs(root: Path) -> list:
    """(mtime, run_id, bytes, path) for every run directory under root."""
    runs = []
    try:
        entries = list(root.iterdir())
    except OSError:
        return runs
    for entry in entries:
        try:
            if entry.is_dir():
                runs.append((entry.stat().st_mtime, entry.name, _dir_bytes(entry), entry))
        except OSError:
            continue
    return sorted(runs, key=lambda r: (r[0], r[1]))


def prune_runs(
    root: Path,
    *,
    now: Optional[float] = None,
    max_bytes: int = F11_B_SESSION_BYTES,
    max_age_seconds: float = RUN_MAX_AGE_SECONDS,
    protect: Iterable[str] = (),
) -> list:
    """Remove run directories oldest-first: first every run older than
    ``max_age_seconds``, then (still oldest-first) until the remaining runs
    total at most ``max_bytes``. Runs named in ``protect`` (the run just
    written) are never removed. The ledger is a file, not a run directory,
    and is never touched. Returns the removed run ids, oldest first."""
    import shutil

    clock = time.time() if now is None else now
    protected = set(protect)
    removed: list = []
    runs = _run_dirs(root)

    def drop(run) -> None:
        shutil.rmtree(run[3], ignore_errors=True)
        removed.append(run[1])

    survivors = []
    for run in runs:
        if run[1] not in protected and clock - run[0] > max_age_seconds:
            drop(run)
        else:
            survivors.append(run)
    total = sum(r[2] for r in survivors)
    for run in survivors:
        if total <= max_bytes:
            break
        if run[1] in protected:
            continue
        drop(run)
        total -= run[2]
    return removed


# ---------------------------------------------------------------------------
# Read-through ledger (ENC-TSK-Q52, FR-10)
# ---------------------------------------------------------------------------


def ledger_path(root: Path) -> Path:
    return root / LEDGER_FILENAME


def validate_ledger_entry(entry: Any, _path: str = "") -> None:
    """Raise ValueError if the entry could carry a key, a body, or a title
    longer than 64 characters (FR-10). Structural, not heuristic: forbidden
    field names are rejected outright and any string over 64 characters is
    refused unless it is the intent_signature join key."""
    if isinstance(entry, dict):
        for name, value in entry.items():
            if str(name).lower() in _LEDGER_FORBIDDEN_KEYS:
                raise ValueError(f"ledger field {_path}{name!r} is forbidden (key/body/title content)")
            validate_ledger_entry(value, f"{_path}{name}.")
            if isinstance(value, str) and len(value) > LEDGER_STRING_MAX and name not in LEDGER_LONG_STRING_KEYS:
                raise ValueError(f"ledger value {_path}{name} exceeds {LEDGER_STRING_MAX} characters")
    elif isinstance(entry, (list, tuple)):
        for index, value in enumerate(entry):
            if isinstance(value, str) and len(value) > LEDGER_STRING_MAX:
                raise ValueError(f"ledger value {_path}[{index}] exceeds {LEDGER_STRING_MAX} characters")
            validate_ledger_entry(value, f"{_path}[{index}].")


def append_ledger(root: Path, entry: dict) -> Path:
    """Append one JSON line to ``<root>/ledger.jsonl``, creating it 0600.
    Raises ValueError (nothing written) for a forbidden entry."""
    validate_ledger_entry(entry)
    root.mkdir(parents=True, exist_ok=True)
    path = ledger_path(root)
    line = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    fd = os.open(str(path), os.O_WRONLY | os.O_APPEND | os.O_CREAT, LEDGER_MODE)
    try:
        os.write(fd, line.encode("utf-8"))
    finally:
        os.close(fd)
    return path


def utc_now_iso(now: Optional[float] = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() if now is None else now))


def run_id_for_path(path: str, root: Path) -> Optional[str]:
    """If ``path`` resolves to a file inside ``<root>/<run_id>/``, return that
    run_id; otherwise None (the read-through no-op path)."""
    try:
        resolved = Path(path).expanduser().resolve()
        relative = resolved.relative_to(root.expanduser().resolve())
    except (OSError, ValueError):
        return None
    parts = relative.parts
    return parts[0] if len(parts) >= 2 else None
