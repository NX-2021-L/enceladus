#!/usr/bin/env python3
"""elr_sync.py -- ELR hash-pinned manifest distribution (ENC-FTR-134 AC-1).

Spec: ENC-TSK-O55. Distributes the ELR runtime file set (elr_lib/*.py,
top-level elr_*.py scripts, elr_contracts.json, README.md) to a local
install directory via a manifest that pins every file's sha256 at an
exact, immutable git commit. Nothing here trusts a branch name, a mutable
tag, or a "latest" pointer -- ``pull`` refuses anything that is not a full
40-character commit sha, and refuses to ACTIVATE an install unless every
listed file verifies byte-for-byte against its recorded hash.

Three subcommands:

  generate-manifest
      Walks tools/elr/ and writes tools/elr/elr_manifest.json: {
        manifest_version, generated_at, source_ref, files: [{path,
        sha256, size_bytes}, ...] }. HARD RULE, encoded and tested: the
      governance dictionary (and any session-cache artifact) can NEVER
      appear in the manifest -- collect_runtime_files() asserts this on
      every candidate path before a manifest is ever built. The manifest
      file never lists itself (its own filename does not match any of
      the four include patterns).

  pull --ref <40-hex sha> [--source github|local:<path>] [--dest DIR]
      Fetches the manifest AT THE PINNED COMMIT, then every listed file
      at that same commit, into a temporary staging directory; verifies
      EVERY file's sha256 against the manifest. Completeness is checked
      BOTH ways: every manifest-listed file must fetch and hash-match
      (a listed-but-missing file refuses with reason "listed-file-missing"
      and a listed-but-wrong-hash file refuses with reason
      "hash-mismatch"), and -- best-effort, via a tree listing at the
      pinned ref -- every actual runtime file that exists at that commit
      must be present in the manifest (an omission refuses with reason
      "manifest-missing-files"). On ALL-verified, staging is swapped into
      --dest atomically (the previous install, if any, is preserved as
      "<dest>.prev"); on ANY failure, staging is discarded and dest is
      left completely untouched -- this is the REFUSE ACTIVATION
      contract. --ref must be a full 40-hex commit sha; a branch name or
      short sha is rejected before any network/local access is attempted
      (pinning means immutable).

  verify [--dest DIR]
      Re-hashes an existing install against the manifest recorded at
      pull time (no network access at all) -- pure local drift
      detection.

Sources:
  github     -- GitHub Contents API (GET .../contents/<path>?ref=<sha>),
                Authorization from env GITHUB_TOKEN, else a `gh api`
                subprocess fallback. The token value is never printed.
  local:PATH -- reads files from a local git checkout at PATH via
                `git -C PATH show <sha>:<path>` (no network). Used for
                tests and the in-task drill.

Python 3.11 standard library only (subprocess to `gh` is the one
permitted auth fallback). Nothing here imports server.py; ELR must run
standalone on any workstation.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol

# Allow running this file directly (python3 tools/elr/elr_sync.py) without
# requiring tools/elr to already be on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from elr_lib.digest import build_digest  # noqa: E402

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_THIS_FILE = Path(__file__).resolve()
ELR_ROOT = _THIS_FILE.parent
REPO_ROOT = ELR_ROOT.parent.parent

REPO_TOOLS_ELR_PATH = "tools/elr"
MANIFEST_FILENAME = "elr_manifest.json"
MANIFEST_REPO_PATH = f"{REPO_TOOLS_ELR_PATH}/{MANIFEST_FILENAME}"
MANIFEST_VERSION = 1

DEFAULT_DEST = "~/.enceladus/elr/bin"
DEFAULT_SOURCE = "github"
GITHUB_REPO = "NX-2021-L/enceladus"

# Metadata file written INTO a successfully-pulled install, recording the
# manifest that install was verified against -- `verify` re-hashes local
# disk contents against this file, entirely offline.
SYNC_MANIFEST_METAFILE = ".elr-sync-manifest.json"

# HARD RULE (ENC-FTR-134 AC-1): the governance dictionary, and anything
# resembling a session-cache artifact, must NEVER be part of the
# distributed runtime file set. Case-insensitive substring match on the
# candidate's own filename/path.
_FORBIDDEN_TOKENS = ("dictionary", "session-cache")

_REF_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def is_forbidden_path(path_or_name: str) -> bool:
    """True if ``path_or_name`` looks like a governance-dictionary or
    session-cache artifact -- the one file class ELR must never
    distribute. Pure function so the HARD RULE is directly unit-testable
    without needing a real dictionary file anywhere on disk.
    """
    lowered = str(path_or_name).lower()
    return any(token in lowered for token in _FORBIDDEN_TOKENS)


def is_valid_ref(ref: Optional[str]) -> bool:
    """A pinned ref must be a full 40-character hex commit sha -- never a
    branch name, tag, or short sha. Pinning means immutable.
    """
    return bool(_REF_RE.match(ref or ""))


# ---------------------------------------------------------------------------
# Runtime file set -- filesystem side (generate-manifest) and path-string
# side (pull's completeness check against a git ls-tree/contents listing).
# Both must encode the SAME include rule: elr_lib/*.py, top-level
# elr_*.py scripts, elr_contracts.json, README.md. Nothing under tests/,
# fixtures/, or __pycache__/ is ever included (those simply never match
# the four patterns below).
# ---------------------------------------------------------------------------


def collect_runtime_files(elr_root: Path) -> List[Path]:
    """Absolute paths of every file that belongs in the distributed
    runtime set, rooted at ``elr_root`` (normally tools/elr). Raises
    AssertionError if any candidate matches the forbidden-path HARD RULE
    -- a defense-in-depth check that fires even though none of today's
    real filenames trip it, so a future filename collision (e.g. an
    "elr_dictionary_helper.py" script) is caught here instead of quietly
    shipping.
    """
    candidates: List[Path] = []
    candidates.extend(sorted(elr_root.glob("elr_*.py")))

    lib_dir = elr_root / "elr_lib"
    if lib_dir.is_dir():
        candidates.extend(sorted(lib_dir.glob("*.py")))

    contracts = elr_root / "elr_contracts.json"
    if contracts.is_file():
        candidates.append(contracts)

    readme = elr_root / "README.md"
    if readme.is_file():
        candidates.append(readme)

    for path in candidates:
        if is_forbidden_path(path.name):
            raise AssertionError(
                f"forbidden path in ELR runtime manifest set: {path} -- the governance "
                "dictionary and session-cache artifacts must NEVER be distributed by elr_sync"
            )

    return sorted(set(candidates), key=lambda p: str(p))


def _matches_runtime_pattern(repo_relative_path: str) -> bool:
    """String-only twin of collect_runtime_files()'s include rule, for
    checking a path returned by a git tree listing (pull's completeness
    check) rather than a real filesystem glob.
    """
    prefix = REPO_TOOLS_ELR_PATH + "/"
    if not repo_relative_path.startswith(prefix):
        return False
    rel = repo_relative_path[len(prefix):]
    if "/" not in rel:
        if rel in ("README.md", "elr_contracts.json"):
            return True
        return rel.startswith("elr_") and rel.endswith(".py")
    parts = rel.split("/")
    return len(parts) == 2 and parts[0] == "elr_lib" and parts[1].endswith(".py")


def _elr_relative_path(repo_relative_path: str) -> str:
    """Strip the "tools/elr/" prefix so a manifest entry's path lands at
    dest/<same-relative-layout> rather than dest/tools/elr/<...>.
    """
    prefix = REPO_TOOLS_ELR_PATH + "/"
    if repo_relative_path.startswith(prefix):
        return repo_relative_path[len(prefix):]
    return repo_relative_path


# ---------------------------------------------------------------------------
# git helpers (used only by generate-manifest, against the LOCAL worktree)
# ---------------------------------------------------------------------------


def git_head_sha(repo_root: Path) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else ""


def git_head_committer_date(repo_root: Path) -> str:
    """ISO-8601 committer date of HEAD -- deterministic (a function of
    which commit is checked out, never of wall-clock "now"), used as the
    default generated_at when --generated-at is not supplied.
    """
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "log", "-1", "--format=%cI", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else ""


# ---------------------------------------------------------------------------
# generate-manifest
# ---------------------------------------------------------------------------


def build_manifest(repo_root: Path, elr_root: Path, generated_at: Optional[str] = None) -> Dict[str, Any]:
    files = collect_runtime_files(elr_root)
    entries: List[Dict[str, Any]] = []
    for path in files:
        data = path.read_bytes()
        entries.append(
            {
                "path": path.relative_to(repo_root).as_posix(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "size_bytes": len(data),
            }
        )
    entries.sort(key=lambda e: e["path"])

    resolved_generated_at = generated_at or git_head_committer_date(repo_root)

    return {
        "manifest_version": MANIFEST_VERSION,
        "generated_at": resolved_generated_at,
        "source_ref": git_head_sha(repo_root),
        "files": entries,
    }


def cmd_generate_manifest(args: argparse.Namespace) -> Dict[str, Any]:
    manifest = build_manifest(REPO_ROOT, ELR_ROOT, args.generated_at)
    out_path = ELR_ROOT / MANIFEST_FILENAME
    out_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return build_digest(
        "elr_sync.generate_manifest",
        True,
        200,
        anomalies=[],
        counts={"file_count": len(manifest["files"])},
        local_path=str(out_path),
        source_ref=manifest["source_ref"],
        manifest_version=manifest["manifest_version"],
    )


# ---------------------------------------------------------------------------
# Sources -- github (network) and local: (git show, no network)
# ---------------------------------------------------------------------------


class ManifestSource(Protocol):
    def read_file(self, repo_relative_path: str, ref: str) -> Optional[bytes]: ...

    def list_tree(self, dir_repo_relative_path: str, ref: str) -> Optional[List[str]]: ...


class LocalGitSource:
    """Reads files/tree listings from a local git checkout at ``repo_path``
    via `git show`/`git ls-tree`. No network. Used for tests and the
    in-task drill (--source local:<path>).
    """

    def __init__(self, repo_path: str):
        self.repo_path = repo_path

    def read_file(self, repo_relative_path: str, ref: str) -> Optional[bytes]:
        proc = subprocess.run(
            ["git", "-C", self.repo_path, "show", f"{ref}:{repo_relative_path}"],
            capture_output=True,
            check=False,
        )
        if proc.returncode != 0:
            return None
        return proc.stdout

    def list_tree(self, dir_repo_relative_path: str, ref: str) -> Optional[List[str]]:
        proc = subprocess.run(
            ["git", "-C", self.repo_path, "ls-tree", "-r", "--name-only", ref, "--", dir_repo_relative_path],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            return None
        return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


class GithubApiSource:
    """Reads files/tree listings from the GitHub Contents API at a pinned
    ref. Auth: env GITHUB_TOKEN first; else a `gh api` subprocess
    fallback. The token value itself is NEVER printed or logged.
    """

    def __init__(self, timeout: int = 20):
        self.timeout = timeout
        self._token = os.environ.get("GITHUB_TOKEN", "").strip()
        self.auth_mode = "env-token" if self._token else "gh-cli-fallback"

    def _contents_url(self, repo_relative_path: str, ref: str) -> str:
        encoded_path = urllib.parse.quote(repo_relative_path)
        return f"https://api.github.com/repos/{GITHUB_REPO}/contents/{encoded_path}?ref={urllib.parse.quote(ref)}"

    def _fetch_json_via_urllib(self, url: str) -> Optional[Any]:
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "enceladus-elr-sync/1.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.getcode() != 200:
                    return None
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            return None

    def _fetch_json_via_gh(self, api_path: str) -> Optional[Any]:
        proc = subprocess.run(
            ["gh", "api", api_path],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            return None
        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError:
            return None

    def _fetch_contents(self, repo_relative_path: str, ref: str) -> Optional[Any]:
        if self._token:
            return self._fetch_json_via_urllib(self._contents_url(repo_relative_path, ref))
        api_path = f"repos/{GITHUB_REPO}/contents/{repo_relative_path}?ref={ref}"
        return self._fetch_json_via_gh(api_path)

    def read_file(self, repo_relative_path: str, ref: str) -> Optional[bytes]:
        body = self._fetch_contents(repo_relative_path, ref)
        if not isinstance(body, dict):
            return None
        content_b64 = body.get("content")
        if not content_b64:
            return None
        try:
            return base64.b64decode(content_b64)
        except (ValueError, TypeError):
            return None

    def list_tree(self, dir_repo_relative_path: str, ref: str) -> Optional[List[str]]:
        """Best-effort recursive directory listing. The Contents API's
        directory form is non-recursive, so this walks one level at a
        time; a failure at any level aborts the WHOLE listing (returns
        None) rather than silently reporting a partial tree as complete
        -- completeness is a correctness check, so a partial result must
        never be mistaken for a full one.
        """
        collected: List[str] = []
        stack = [dir_repo_relative_path]
        while stack:
            current = stack.pop()
            body = self._fetch_contents(current, ref)
            if not isinstance(body, list):
                return None
            for entry in body:
                if not isinstance(entry, dict):
                    return None
                entry_type = entry.get("type")
                entry_path = entry.get("path")
                if not entry_path:
                    return None
                if entry_type == "dir":
                    stack.append(entry_path)
                elif entry_type == "file":
                    collected.append(entry_path)
        return collected


def build_source(source_spec: str) -> ManifestSource:
    spec = (source_spec or "").strip()
    if spec == "github":
        return GithubApiSource()
    if spec.startswith("local:"):
        path = spec[len("local:"):]
        if not path:
            raise ValueError("local: source requires a path, e.g. local:/path/to/checkout")
        return LocalGitSource(path)
    raise ValueError(f"unknown --source {source_spec!r}; expected 'github' or 'local:<path>'")


# ---------------------------------------------------------------------------
# pull
# ---------------------------------------------------------------------------


def _refusal_digest(operation: str, status: int, reason: str, violations: List[Dict[str, Any]], **extra: Any) -> Dict[str, Any]:
    return build_digest(
        operation,
        False,
        status,
        refusal={"reason": reason, "missing_fields": [], "violations": violations},
        **extra,
    )


def pull_manifest_at_ref(ref: str, source_spec: str, dest: str, *, timeout: int = 20) -> Dict[str, Any]:
    operation = "elr_sync.pull"

    if not is_valid_ref(ref):
        return _refusal_digest(
            operation,
            400,
            "ref-not-40-hex",
            [{"path": "ref", "reason": f"{ref!r} is not a 40-character hex commit sha -- pinning means immutable"}],
            source_ref=ref,
            anomalies=[],
        )

    try:
        source = build_source(source_spec)
    except ValueError as exc:
        return _refusal_digest(
            operation, 400, "unknown-source", [{"path": "source", "reason": str(exc)}], source_ref=ref, anomalies=[]
        )
    if isinstance(source, GithubApiSource):
        source.timeout = timeout

    manifest_bytes = source.read_file(MANIFEST_REPO_PATH, ref)
    if manifest_bytes is None:
        return _refusal_digest(
            operation,
            404,
            "manifest-fetch-failed",
            [{"path": MANIFEST_REPO_PATH, "reason": "could not fetch the manifest at the pinned ref"}],
            source_ref=ref,
            anomalies=[],
        )

    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return _refusal_digest(
            operation,
            422,
            "manifest-invalid",
            [{"path": MANIFEST_REPO_PATH, "reason": str(exc)}],
            source_ref=ref,
            anomalies=[],
        )

    files = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(files, list) or not files:
        return _refusal_digest(
            operation,
            422,
            "manifest-invalid",
            [{"path": "files", "reason": "manifest.files is missing, empty, or not a list"}],
            source_ref=ref,
            manifest_version=manifest.get("manifest_version") if isinstance(manifest, dict) else None,
            anomalies=[],
        )

    # --- Completeness, direction 2: does the manifest OMIT a real
    # runtime file that exists at this ref? Best-effort -- a listing
    # failure (e.g. no GitHub credentials configured) degrades to an
    # anomaly, never a hard block on its own; it is direction 1 (every
    # LISTED file verifies) that is unconditionally load-bearing.
    completeness_anomalies: List[str] = []
    manifest_paths = {entry.get("path") for entry in files if isinstance(entry, dict)}
    tree_paths = source.list_tree(REPO_TOOLS_ELR_PATH, ref)

    if tree_paths is None:
        completeness_anomalies.append("completeness-check-unavailable: tree listing failed")
    else:
        expected = {p for p in tree_paths if _matches_runtime_pattern(p) and not is_forbidden_path(p)}
        missing_from_manifest = sorted(expected - manifest_paths)
        if missing_from_manifest:
            return _refusal_digest(
                operation,
                422,
                "manifest-missing-files",
                [
                    {"path": p, "reason": "present in the runtime file set at this ref but absent from the manifest"}
                    for p in missing_from_manifest
                ],
                mismatched=missing_from_manifest,
                source_ref=ref,
                manifest_version=manifest.get("manifest_version"),
                anomalies=[],
            )

    # --- Stage + verify, direction 1: every LISTED file must fetch and
    # hash-match. All entries are checked (never short-circuited) so a
    # refusal names every offending path, not just the first.
    dest_path = Path(dest).expanduser()
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    staging_dir = dest_path.parent / f".{dest_path.name}.staging-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    staging_dir.mkdir(parents=True, exist_ok=False)

    files_verified = 0
    mismatched: List[str] = []
    violations: List[Dict[str, Any]] = []
    any_hash_mismatch = False

    try:
        for entry in files:
            rel_path = entry.get("path") if isinstance(entry, dict) else None
            expected_sha = str(entry.get("sha256") or "").strip().lower() if isinstance(entry, dict) else ""
            expected_size = entry.get("size_bytes") if isinstance(entry, dict) else None

            if not rel_path or not expected_sha:
                mismatched.append(rel_path or "<unnamed-entry>")
                violations.append({"path": rel_path, "reason": "manifest entry missing path or sha256"})
                any_hash_mismatch = True
                continue

            content = source.read_file(rel_path, ref)
            if content is None:
                mismatched.append(rel_path)
                violations.append({"path": rel_path, "reason": "listed in manifest but fetch failed at the pinned ref"})
                continue

            actual_sha = hashlib.sha256(content).hexdigest()
            if actual_sha != expected_sha:
                mismatched.append(rel_path)
                violations.append(
                    {"path": rel_path, "reason": f"sha256 mismatch: expected {expected_sha}, got {actual_sha}"}
                )
                any_hash_mismatch = True
                continue
            if isinstance(expected_size, int) and expected_size != len(content):
                mismatched.append(rel_path)
                violations.append(
                    {"path": rel_path, "reason": f"size_bytes mismatch: expected {expected_size}, got {len(content)}"}
                )
                any_hash_mismatch = True
                continue

            out_path = staging_dir / _elr_relative_path(rel_path)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(content)
            files_verified += 1

        if mismatched:
            reason = "hash-mismatch" if any_hash_mismatch else "listed-file-missing"
            status = 409 if any_hash_mismatch else 404
            return _refusal_digest(
                operation,
                status,
                reason,
                violations,
                mismatched=sorted(set(mismatched)),
                files_verified=files_verified,
                files_failed=len(mismatched),
                dest=str(dest_path),
                source_ref=ref,
                manifest_version=manifest.get("manifest_version"),
                anomalies=completeness_anomalies,
            )

        # --- ALL VERIFIED: atomic swap. Previous install (if any) is
        # preserved as "<dest>.prev"; dest is never touched before this
        # point on any refusal path above.
        prev_path = dest_path.parent / f"{dest_path.name}.prev"
        if dest_path.exists():
            if prev_path.exists():
                shutil.rmtree(prev_path)
            os.rename(dest_path, prev_path)
        os.rename(staging_dir, dest_path)

        meta = dict(manifest)
        meta["_pulled_source_ref"] = ref
        (dest_path / SYNC_MANIFEST_METAFILE).write_text(json.dumps(meta, sort_keys=True), encoding="utf-8")

        return build_digest(
            operation,
            True,
            200,
            anomalies=completeness_anomalies,
            files_verified=files_verified,
            files_failed=0,
            dest=str(dest_path),
            source_ref=ref,
            manifest_version=manifest.get("manifest_version"),
        )
    finally:
        if staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# verify -- pure local drift detection, no network
# ---------------------------------------------------------------------------


def verify_install(dest: str) -> Dict[str, Any]:
    operation = "elr_sync.verify"
    dest_path = Path(dest).expanduser()
    meta_path = dest_path / SYNC_MANIFEST_METAFILE

    if not meta_path.is_file():
        return _refusal_digest(
            operation,
            404,
            "no-recorded-manifest",
            [{"path": str(meta_path), "reason": "no elr_sync install recorded at this dest"}],
            dest=str(dest_path),
            anomalies=[],
        )

    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return _refusal_digest(
            operation,
            422,
            "recorded-manifest-invalid",
            [{"path": str(meta_path), "reason": str(exc)}],
            dest=str(dest_path),
            anomalies=[],
        )

    files = meta.get("files") if isinstance(meta, dict) else None
    files = files if isinstance(files, list) else []

    files_verified = 0
    mismatched: List[str] = []
    violations: List[Dict[str, Any]] = []

    for entry in files:
        rel_path = entry.get("path") if isinstance(entry, dict) else None
        expected_sha = str(entry.get("sha256") or "").strip().lower() if isinstance(entry, dict) else ""
        if not rel_path:
            continue
        local_path = dest_path / _elr_relative_path(rel_path)

        if not local_path.is_file():
            mismatched.append(rel_path)
            violations.append({"path": rel_path, "reason": "file missing from install (drift)"})
            continue

        actual_sha = hashlib.sha256(local_path.read_bytes()).hexdigest()
        if actual_sha != expected_sha:
            mismatched.append(rel_path)
            violations.append(
                {"path": rel_path, "reason": f"drift detected: on-disk sha256 {actual_sha} != recorded {expected_sha}"}
            )
            continue

        files_verified += 1

    common_fields = dict(
        files_verified=files_verified,
        files_failed=len(mismatched),
        dest=str(dest_path),
        source_ref=meta.get("_pulled_source_ref") or meta.get("source_ref"),
        manifest_version=meta.get("manifest_version"),
    )

    if mismatched:
        return _refusal_digest(
            operation,
            409,
            "drift-detected",
            violations,
            mismatched=sorted(set(mismatched)),
            anomalies=[],
            **common_fields,
        )

    return build_digest(operation, True, 200, anomalies=[], **common_fields)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    # ALL ELR CLIs must set allow_abbrev=False so partial/ambiguous flags
    # are never silently accepted.
    parser = argparse.ArgumentParser(
        prog="elr_sync",
        description=(
            "ELR hash-pinned manifest distribution: generate a runtime-file manifest, "
            "pull it (and every listed file) at an immutable commit with refuse-on-mismatch "
            "activation, or verify an existing install for drift. Digest-only output."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--timeout", type=int, default=20, help="Network request timeout in seconds (default: 20).")

    subparsers = parser.add_subparsers(dest="command", required=True)

    gen_parser = subparsers.add_parser(
        "generate-manifest",
        help="Walk tools/elr/ and (re)write tools/elr/elr_manifest.json.",
        allow_abbrev=False,
    )
    gen_parser.add_argument(
        "--generated-at",
        default=None,
        help="Override generated_at (ISO-8601). Default: HEAD's committer date (deterministic).",
    )

    pull_parser = subparsers.add_parser(
        "pull",
        help="Fetch the manifest and every listed file at a pinned commit; refuse activation on any mismatch.",
        allow_abbrev=False,
    )
    pull_parser.add_argument("--ref", required=True, help="Full 40-hex commit sha to pin to (required).")
    pull_parser.add_argument(
        "--source",
        default=DEFAULT_SOURCE,
        help=f"'github' or 'local:<path>' (default: {DEFAULT_SOURCE}).",
    )
    pull_parser.add_argument(
        "--dest", default=DEFAULT_DEST, help=f"Install destination directory (default: {DEFAULT_DEST})."
    )

    verify_parser = subparsers.add_parser(
        "verify",
        help="Re-hash an existing install against its recorded manifest (no network).",
        allow_abbrev=False,
    )
    verify_parser.add_argument(
        "--dest", default=DEFAULT_DEST, help=f"Install directory to verify (default: {DEFAULT_DEST})."
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "generate-manifest":
        digest = cmd_generate_manifest(args)
    elif args.command == "pull":
        digest = pull_manifest_at_ref(args.ref, args.source, args.dest, timeout=args.timeout)
    elif args.command == "verify":
        digest = verify_install(args.dest)
    else:  # pragma: no cover -- argparse enforces choices via subparsers
        parser.error(f"unknown command {args.command!r}")
        return 2

    print(json.dumps(digest, sort_keys=True))
    return 0 if digest.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
