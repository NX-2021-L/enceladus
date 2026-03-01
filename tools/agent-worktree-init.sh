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
# Environment variables:
#   ENCELADUS_AGENT_PROVIDER  — agent identity (default: "unknown")

set -euo pipefail

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
# ---------------------------------------------------------------------------
ACTIVE_COUNT=0
for lockfile in "$LOCK_DIR"/*.lock; do
  [ -f "$lockfile" ] || continue
  LOCK_PID="$(grep '^pid=' "$lockfile" | cut -d= -f2)"
  LOCK_WT="$(grep '^worktree=' "$lockfile" | cut -d= -f2)"
  LOCK_PROV="$(grep '^provider=' "$lockfile" | cut -d= -f2)"

  if kill -0 "$LOCK_PID" 2>/dev/null; then
    ACTIVE_COUNT=$((ACTIVE_COUNT + 1))
    echo "[WARN] Active session: $LOCK_PROV (PID $LOCK_PID) in $LOCK_WT"
  else
    # Fix D.4: read branch BEFORE removing the lock file to avoid read-after-delete.
    LOCK_BRANCH="$(grep '^branch=' "$lockfile" 2>/dev/null | cut -d= -f2 || true)"
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
  fi
done

if [ "$ACTIVE_COUNT" -gt 0 ]; then
  echo "[WARN] $ACTIVE_COUNT other agent session(s) active. Worktree isolation is protecting you."
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
if [ -d "$WORKTREE_PATH" ]; then
  echo "[INFO] Worktree directory already exists at $WORKTREE_PATH. Reusing."
elif git -C "$REPO_ROOT" show-ref --verify "refs/heads/$BRANCH_NAME" >/dev/null 2>&1; then
  # Branch exists but worktree dir does not — stale branch from a killed session.
  echo "[WARN] Branch '$BRANCH_NAME' already exists without a worktree directory."
  echo "[INFO] Reusing existing branch for new worktree..."
  git -C "$REPO_ROOT" worktree add "$WORKTREE_PATH" "$BRANCH_NAME"
  echo "[SUCCESS] Worktree created at $WORKTREE_PATH (reusing existing branch)"
else
  git -C "$REPO_ROOT" worktree add -b "$BRANCH_NAME" "$WORKTREE_PATH" HEAD
  echo "[SUCCESS] Worktree created at $WORKTREE_PATH"
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
echo ""
echo ">>> cd $WORKTREE_PATH"
