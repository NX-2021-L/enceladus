#!/usr/bin/env bash
# agent-worktree-init.sh — Create an isolated git worktree for the current agent session.
#
# Usage:
#   source tools/agent-worktree-init.sh [session-name]
#
# Creates a worktree at .claude/worktrees/{session-id}/ with a unique branch,
# writes a lock file at .claude/agent-locks/{session-id}.lock, and prints the
# worktree path. The calling agent should cd into the printed path.
#
# If already inside a worktree, exits with success (idempotent).
# Detects other active sessions and warns. Cleans up stale locks.
#
# ENC-TSK-O39: the "reuse" path for an existing $WORKTREE_PATH directory now
# verifies the directory is a REGISTERED worktree (present in `git worktree
# list --porcelain` with a resolving .git link) before reusing it. A path
# that exists but isn't registered (e.g. left behind after `rm -rf` of a
# worktree without `git worktree remove`/prune) is treated as an orphan: its
# contents are preserved by renaming to "$WORKTREE_PATH.orphan-<UTC
# timestamp>" (never deleted silently), `git worktree prune` is run, and a
# fresh worktree is created in its place.
#
# ENC-TSK-O39: lock heartbeat. The lock file's mtime drives the
# STALE_LOCK_AGE_SECONDS age gate below (ENC-ISS-632). A session doing
# legitimate long-running work past that window may `touch` its own lock
# file (`.claude/agent-locks/<session-id>.lock`) at any point to refresh the
# mtime and avoid being swept by a later invocation's age gate -- this script
# does so once after writing the lock, and a session may repeat it anytime
# before it releases the worktree.
#
# Environment variables:
#   ENCELADUS_AGENT_PROVIDER  — agent identity (default: "unknown")

set -euo pipefail

# ---------------------------------------------------------------------------
# ENC-TSK-T28: lock-file reading lives in a sourceable library so the
# classification can be tested without running this script's side effects.
# See tools/lib/agent-lock.selftest.sh. BASH_SOURCE resolves correctly whether
# this file is executed or `source`d, which the usage note above allows.
# ---------------------------------------------------------------------------
_AWI_LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/agent-lock.sh"
if [ ! -r "$_AWI_LIB" ]; then
  echo "[ERROR] Missing required library: $_AWI_LIB" >&2
  exit 1
fi
# shellcheck source=tools/lib/agent-lock.sh
. "$_AWI_LIB"

# ---------------------------------------------------------------------------
# Resolve repo root (the main checkout, not a worktree)
# ---------------------------------------------------------------------------
GIT_COMMON_DIR="$(git rev-parse --git-common-dir 2>/dev/null)"
if [ -z "$GIT_COMMON_DIR" ]; then
  echo "[ERROR] Not inside a git repository." >&2
  exit 1
fi
REPO_ROOT="$(cd "$GIT_COMMON_DIR/.." && pwd)"

# ---------------------------------------------------------------------------
# Idempotency: if already in a worktree, nothing to do
# ---------------------------------------------------------------------------
CURRENT_TOPLEVEL="$(git rev-parse --show-toplevel 2>/dev/null)"
if [ "$CURRENT_TOPLEVEL" != "$REPO_ROOT" ]; then
  echo "[INFO] Already in a git worktree ($CURRENT_TOPLEVEL). No action needed."
  exit 0
fi

# ---------------------------------------------------------------------------
# Session identity
# Fix D.1: use $1 arg for both SESSION_ID and BRANCH_NAME when provided.
# When no arg is given, fall back to PROVIDER/TIMESTAMP and warn.
# ---------------------------------------------------------------------------
PROVIDER="${ENCELADUS_AGENT_PROVIDER:-unknown}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"

if [ -n "${1:-}" ]; then
  SESSION_ID="$1"
  BRANCH_NAME="agent/$1"
else
  SESSION_ID="${PROVIDER}-${TIMESTAMP}-$$"
  BRANCH_NAME="agent/${PROVIDER}/${TIMESTAMP}"
  echo "[WARN] No session name provided. Using timestamp-based branch: $BRANCH_NAME"
  echo "[WARN] For task work, pass a session name: agent-worktree-init.sh <TRACKER-ID>-<slug>"
fi

# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------
WORKTREE_DIR="$REPO_ROOT/.claude/worktrees"
LOCK_DIR="$REPO_ROOT/.claude/agent-locks"
mkdir -p "$WORKTREE_DIR" "$LOCK_DIR"

# ---------------------------------------------------------------------------
# Detect active sessions & clean stale locks
#
# ENC-ISS-632: the pid recorded in a lock file is the ephemeral
# `bash agent-worktree-init.sh` subprocess itself, which exits the instant the
# script returns -- long before the owning agent session's work is done.
# Treating a dead pid as proof of a dead session made every lock look stale
# within moments of being written, so any later invocation (by the same or a
# sibling session) force-removed active worktrees and deleted unpushed
# branches out from under in-flight sessions (destroyed three worktrees and
# two sibling branches on 2026-08-21). A lock is only swept once ALL of the
# following hold; any failing check skips that lock for this run and leaves
# it for a later sweep to re-evaluate:
#
#   1. Age gate: the lock file is at least STALE_LOCK_AGE_SECONDS old. This
#      bounds the blast radius of the still-imperfect pid signal to locks old
#      enough that the owning invocation has almost certainly finished.
#   2. Clean-worktree gate: the worktree has no uncommitted changes
#      (`git status --porcelain` is empty).
#   3. Pushed-branch gate: the branch carries no commits absent from every
#      remote-tracking ref (`git log <branch> --not --remotes` is empty).
# ---------------------------------------------------------------------------
STALE_LOCK_AGE_SECONDS=21600  # 6 hours (ENC-ISS-632)

ACTIVE_COUNT=0
UNREADABLE_COUNT=0
for lockfile in "$LOCK_DIR"/*.lock; do
  [ -f "$lockfile" ] || continue
  # ENC-TSK-T28: read every field through agent_lock_field, which cannot fail.
  # These were bare `grep ... | cut` command substitutions, and `grep` exits 1
  # when it matches nothing -- so under this script's own `set -euo pipefail` a
  # single lock file not in key=value form aborted the entire invocation here,
  # before "[INFO] Fetching origin...", leaving no worktree and exit 1. Three
  # such files have been present in this repository since August 2026, so step
  # 0.2 of the documented bootstrap was failing for every session.
  LOCK_PID="$(agent_lock_field "$lockfile" pid)"
  LOCK_WT="$(agent_lock_field "$lockfile" worktree)"
  LOCK_PROV="$(agent_lock_field "$lockfile" provider)"
  LOCK_STATE="$(agent_lock_classify "$lockfile")"

  # ENC-TSK-T28: a lock with no usable pid is UNKNOWN -- neither live nor
  # provably dead -- and is reported without being counted as an active session
  # and without being swept. It is not counted because a stale file should not
  # masquerade as a colleague at work: the three legacy files above reported as
  # "Active session: ... (PID 0)" on every run for months, because `kill -0 0`
  # signals the caller's own process group and therefore succeeds. It is not
  # swept because the sweep below force-removes a worktree and deletes an
  # unpushed branch, and ENC-ISS-632 is the record of that going wrong when the
  # pid signal was trusted too readily; the case where we know least about the
  # owner is the last place to act destructively.
  if [ "$LOCK_STATE" = "unknown" ]; then
    UNREADABLE_COUNT=$((UNREADABLE_COUNT + 1))
    echo "[WARN] Unreadable lock (no usable pid), left untouched: $(basename "$lockfile")${LOCK_PROV:+ provider=$LOCK_PROV}"
    continue
  fi

  if [ "$LOCK_STATE" = "live" ]; then
    ACTIVE_COUNT=$((ACTIVE_COUNT + 1))
    echo "[WARN] Active session: $LOCK_PROV (PID $LOCK_PID) in $LOCK_WT"
    continue
  fi

  # Fix D.4: read branch BEFORE removing the lock file to avoid read-after-delete.
  LOCK_BRANCH="$(agent_lock_field "$lockfile" branch)"

  # Gate 1 (ENC-ISS-632): age -- macOS/BSD stat uses -f %m, GNU stat uses -c %Y.
  LOCK_MTIME="$(stat -f %m "$lockfile" 2>/dev/null || stat -c %Y "$lockfile" 2>/dev/null || echo 0)"
  LOCK_AGE=$(( $(date +%s) - LOCK_MTIME ))
  if [ "$LOCK_AGE" -lt "$STALE_LOCK_AGE_SECONDS" ]; then
    ACTIVE_COUNT=$((ACTIVE_COUNT + 1))
    echo "[WARN] Lock younger than ${STALE_LOCK_AGE_SECONDS}s; treating as ACTIVE despite dead pid (ENC-ISS-632): $LOCK_PROV in $LOCK_WT"
    continue
  fi

  # Gate 2 (ENC-ISS-632): never destroy uncommitted work.
  if [ -d "$LOCK_WT" ] && [ -n "$(git -C "$LOCK_WT" status --porcelain 2>/dev/null)" ]; then
    echo "[WARN] Stale-aged lock but worktree has uncommitted changes; NOT removing (ENC-ISS-632): $LOCK_WT"
    continue
  fi

  # Gate 3 (ENC-ISS-632): never delete a branch with commits absent from every remote.
  if [ -n "$LOCK_BRANCH" ] && [ -n "$(git -C "$REPO_ROOT" log "$LOCK_BRANCH" --not --remotes --oneline -1 2>/dev/null)" ]; then
    echo "[WARN] Stale-aged lock but branch has unpushed commits; NOT removing (ENC-ISS-632): $LOCK_BRANCH"
    continue
  fi

  echo "[INFO] Cleaning stale lock for PID $LOCK_PID ($LOCK_PROV)"
  rm -f "$lockfile"
  if [ -d "$LOCK_WT" ]; then
    git -C "$REPO_ROOT" worktree remove --force "$LOCK_WT" 2>/dev/null || true
  fi
  # Prune the branch only if it was never pushed to origin
  if [ -n "$LOCK_BRANCH" ]; then
    HAS_REMOTE="$(git -C "$REPO_ROOT" branch -r --list "origin/${LOCK_BRANCH#refs/heads/}" 2>/dev/null)"
    if [ -z "$HAS_REMOTE" ]; then
      git -C "$REPO_ROOT" branch -D "$LOCK_BRANCH" 2>/dev/null || true
      echo "[INFO] Removed unpushed stale branch: $LOCK_BRANCH"
    fi
  fi
done

if [ "$ACTIVE_COUNT" -gt 0 ]; then
  echo "[WARN] $ACTIVE_COUNT other agent session(s) active. Worktree isolation is protecting you."
fi

# ENC-TSK-T28: reported separately from ACTIVE_COUNT on purpose. These are not
# sessions at work, so folding them into that number overstates what is running
# and tells the reader nothing about what to do; naming them as unreadable
# points at the fix, which is for a human to inspect and delete the files.
if [ "$UNREADABLE_COUNT" -gt 0 ]; then
  echo "[WARN] $UNREADABLE_COUNT lock file(s) in $LOCK_DIR carry no usable pid. They are NOT counted as active sessions and were NOT swept."
  echo "[WARN] They block nothing. Inspect and remove them by hand once you are satisfied the worktree and branch each names are finished with."
fi

# ---------------------------------------------------------------------------
# Fix D.2: Sync with origin/main so the new worktree starts from latest main
# ---------------------------------------------------------------------------
echo "[INFO] Fetching origin..."
git -C "$REPO_ROOT" fetch origin 2>&1 | sed 's/^/  /'
if git -C "$REPO_ROOT" show-ref --verify refs/remotes/origin/main >/dev/null 2>&1; then
  git -C "$REPO_ROOT" merge --ff-only origin/main 2>&1 | sed 's/^/  /' || {
    echo "[WARN] Fast-forward merge of origin/main failed (main checkout may have local commits)."
    echo "[WARN] New worktree will be created from current HEAD -- may be behind origin/main."
  }
fi

# ---------------------------------------------------------------------------
# Create worktree
# ---------------------------------------------------------------------------
WORKTREE_PATH="$WORKTREE_DIR/$SESSION_ID"

# Fix D.3: Handle three cases to avoid exit-128 when branch already exists.
# ENC-TSK-O39: the case where $WORKTREE_PATH already exists is split into
# "registered worktree" (safe to reuse) vs. "orphan directory" (must be
# preserved, never silently reused or deleted).
create_fresh_worktree() {
  if git -C "$REPO_ROOT" show-ref --verify "refs/heads/$BRANCH_NAME" >/dev/null 2>&1; then
    # Branch exists but worktree dir does not — stale branch from a killed session.
    echo "[WARN] Branch '$BRANCH_NAME' already exists without a worktree directory."
    echo "[INFO] Reusing existing branch for new worktree..."
    git -C "$REPO_ROOT" worktree add "$WORKTREE_PATH" "$BRANCH_NAME"
    echo "[SUCCESS] Worktree created at $WORKTREE_PATH (reusing existing branch)"
  else
    git -C "$REPO_ROOT" worktree add -b "$BRANCH_NAME" "$WORKTREE_PATH" HEAD
    echo "[SUCCESS] Worktree created at $WORKTREE_PATH"
  fi
}

if [ -d "$WORKTREE_PATH" ]; then
  # ENC-TSK-O39, orphan-reuse detection: bare directory existence is not
  # proof this is a live worktree. Verify it's registered with the main
  # checkout's git AND that its .git link actually resolves before reusing.
  if git -C "$REPO_ROOT" worktree list --porcelain | grep -Fxq "worktree $WORKTREE_PATH" \
    && [ -f "$WORKTREE_PATH/.git" ] \
    && git -C "$WORKTREE_PATH" rev-parse --git-dir >/dev/null 2>&1; then
    echo "[INFO] Worktree directory already exists at $WORKTREE_PATH and is a registered worktree. Reusing."
  else
    ORPHAN_PATH="${WORKTREE_PATH}.orphan-$(date -u +%Y%m%dT%H%M%SZ)"
    echo "[WARN] Directory exists at $WORKTREE_PATH but is NOT a registered git worktree (orphan left by a destroyed worktree, or a broken .git link)."
    echo "[INFO] Preserving orphan contents (never deleting silently): $WORKTREE_PATH -> $ORPHAN_PATH"
    mv "$WORKTREE_PATH" "$ORPHAN_PATH"
    git -C "$REPO_ROOT" worktree prune
    create_fresh_worktree
    echo "[INFO] Orphan directory preserved at $ORPHAN_PATH for manual inspection/cleanup."
  fi
else
  create_fresh_worktree
fi

# ---------------------------------------------------------------------------
# Write lock file
# Fix D.5: include task_id field for improved session traceability.
# ---------------------------------------------------------------------------
cat > "$LOCK_DIR/$SESSION_ID.lock" <<EOF
pid=$$
provider=$PROVIDER
started=$TIMESTAMP
worktree=$WORKTREE_PATH
branch=$BRANCH_NAME
task_id=${1:-}
EOF

echo "[SUCCESS] Lock file written: $LOCK_DIR/$SESSION_ID.lock"

# ENC-TSK-O39: lock heartbeat. Refresh the mtime now (redundant right after
# the write above, but establishes the pattern) so long-running sessions know
# they can re-run this same `touch` at any later point to stay outside the
# STALE_LOCK_AGE_SECONDS age gate (ENC-ISS-632) without needing a live PID.
touch "$LOCK_DIR/$SESSION_ID.lock"

echo ""
echo ">>> cd $WORKTREE_PATH"
