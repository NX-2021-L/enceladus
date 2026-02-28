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
# ---------------------------------------------------------------------------
PROVIDER="${ENCELADUS_AGENT_PROVIDER:-unknown}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SESSION_ID="${1:-${PROVIDER}-${TIMESTAMP}-$$}"
BRANCH_NAME="agent/${PROVIDER}/${TIMESTAMP}"

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
    # Stale lock — clean up
    echo "[INFO] Cleaning stale lock for PID $LOCK_PID ($LOCK_PROV)"
    rm -f "$lockfile"
    if [ -d "$LOCK_WT" ]; then
      git -C "$REPO_ROOT" worktree remove --force "$LOCK_WT" 2>/dev/null || true
    fi
    # Also prune the branch if it was never pushed
    LOCK_BRANCH="$(grep '^branch=' "$lockfile" 2>/dev/null | cut -d= -f2 || true)"
    if [ -n "$LOCK_BRANCH" ]; then
      git -C "$REPO_ROOT" branch -D "$LOCK_BRANCH" 2>/dev/null || true
    fi
  fi
done

if [ "$ACTIVE_COUNT" -gt 0 ]; then
  echo "[WARN] $ACTIVE_COUNT other agent session(s) active. Worktree isolation is protecting you."
fi

# ---------------------------------------------------------------------------
# Create worktree
# ---------------------------------------------------------------------------
WORKTREE_PATH="$WORKTREE_DIR/$SESSION_ID"

if [ -d "$WORKTREE_PATH" ]; then
  echo "[INFO] Worktree already exists at $WORKTREE_PATH. Reusing."
else
  git -C "$REPO_ROOT" worktree add -b "$BRANCH_NAME" "$WORKTREE_PATH" HEAD
  echo "[SUCCESS] Worktree created at $WORKTREE_PATH"
fi

# ---------------------------------------------------------------------------
# Write lock file
# ---------------------------------------------------------------------------
cat > "$LOCK_DIR/$SESSION_ID.lock" <<EOF
pid=$$
provider=$PROVIDER
started=$TIMESTAMP
worktree=$WORKTREE_PATH
branch=$BRANCH_NAME
EOF

echo "[SUCCESS] Lock file written: $LOCK_DIR/$SESSION_ID.lock"
echo ""
echo ">>> cd $WORKTREE_PATH"
