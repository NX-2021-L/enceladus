#!/usr/bin/env python3
"""elr_provision_key.py -- write ELR's own key file (ENC-TSK-Q35 / ENC-ISS-831).

io runs this once per host; agents never do. It reads the internal API key
from piped stdin (or an interactive no-echo prompt), writes it atomically to
the ELR key file -- ~/.enceladus/internal_key, or $ENCELADUS_ELR_KEY_FILE, or
--path -- at mode 0600, and prints a one-line digest with the path, mode and
byte count. The key itself is never printed, logged, or echoed.

After this, every ELR entry point (the elr launcher, a direct
``python3 elr_<sub>.py``, a subagent, a Workflow) resolves the key in
elr_lib.config, with no dependence on ~/.claude.json or any MCP launcher.

Usage:
    python3 tools/elr/elr_provision_key.py              # prompts, no echo
    printf '%s' "$KEY" | python3 tools/elr/elr_provision_key.py
    python3 tools/elr/elr_provision_key.py --force      # replace an existing file

Exit codes: 0 written, 1 refused (empty/malformed key, or the file exists
without --force), 2 write failed.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

from elr_lib import config as elr_config  # noqa: E402
from elr_lib.digest import build_digest  # noqa: E402

OPERATION = "elr_provision_key.write"
MIN_KEY_LENGTH = 16


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Write the ELR key file at mode 0600 (io-run; never prints the key).",
        allow_abbrev=False,
    )
    parser.add_argument("--path", help="Key file to write (default: $ENCELADUS_ELR_KEY_FILE or ~/.enceladus/internal_key).")
    parser.add_argument("--force", action="store_true", help="Replace an existing key file.")
    return parser


def _read_key() -> str:
    if sys.stdin is not None and not sys.stdin.isatty():
        return sys.stdin.read().strip()
    return getpass.getpass("ELR internal API key (input hidden): ").strip()


def _key_problem(value: str) -> Optional[str]:
    if not value:
        return "empty key"
    if any(ch.isspace() for ch in value):
        return "key contains whitespace (expected a single token)"
    if len(value) < MIN_KEY_LENGTH:
        return f"key shorter than {MIN_KEY_LENGTH} characters"
    return None


def write_key_file(path: Path, value: str) -> None:
    """Atomic owner-only write: O_EXCL temp file at 0600, fsync, rename."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(value + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    path = Path(args.path).expanduser() if args.path else elr_config.elr_key_file_path()

    if path.exists() and not args.force:
        print(json.dumps(build_digest(
            OPERATION, False, 409, anomalies=[f"key_file_exists: {path} (pass --force to replace)"], local_path=str(path),
        ), sort_keys=True))
        return 1

    value = _read_key()
    problem = _key_problem(value)
    if problem:
        print(json.dumps(build_digest(OPERATION, False, 400, anomalies=[problem], local_path=str(path)), sort_keys=True))
        return 1

    try:
        write_key_file(path, value)
    except OSError as exc:
        print(json.dumps(build_digest(
            OPERATION, False, 500, anomalies=[f"write_failed: {exc.__class__.__name__}"], local_path=str(path),
        ), sort_keys=True))
        return 2

    mode = oct(path.stat().st_mode & 0o777)
    print(json.dumps(build_digest(
        OPERATION,
        True,
        200,
        local_path=str(path),
        size_bytes=path.stat().st_size,
        key_source="key_file",
        remediation=f"mode {mode}; verify with: ~/.enceladus/elr/elr smoke --all-profiles",
    ), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
