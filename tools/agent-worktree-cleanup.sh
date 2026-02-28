#!/usr/bin/env bash
# agent-worktree-cleanup.sh — Remove lock file and worktree for an agent session.
#
# Usage:
#   tools/agent-worktree-cleanup.sh <session-id>
#   tools/agent-worktree-cleanup.sh --self        # auto-detect from CWD
#   tools/agent-worktree-cleanup.sh --stale       # clean all stale (dead PID) sessions
#
# Removes the lock file from .claude/agent-locks/ and the worktree from
# .claude/worktrees/. If the worktree branch was never pushed, also deletes
# the local branch.

set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve repo root
# ---------------------------------------------------------------------------
GIT_COMMON_DIR="$(git rev-parse --git-common-dir 2>/dev/null)"
if [ -z "$GIT_COMMON_DIR" ]; then
  echo "[ERROR] Not inside a git repository." >&2
  exit 1
fi
REPO_ROOT="$(cd "$GIT_COMMON_DIR/.." && pwd)"

LOCK_DIR="$REPO_ROOT/.claude/agent-locks"
WORKTREE_DIR="$REPO_ROOT/.claude/worktrees"

# ---------------------------------------------------------------------------
# Helper: clean up a single session by lock file path
# ---------------------------------------------------------------------------
cleanup_session() {
  local lockfile="$1"
  [ -f "$lockfile" ] || return 0

  local session_id
  session_id="$(basename "$lockfile" .lock)"
  local wt_path
  wt_path="$(grep '^worktree=' "$lockfile" | cut -d= -f2)"
  local branch
  branch="$(grep '^branch=' "$lockfile" | cut -d= -f2)"

  # Remove lock file
  rm -f "$lockfile"
  echo "[OK] Removed lock: $lockfile"

  # Remove worktree
  if [ -d "$wt_path" ]; then
    # cd out of worktree if we're inside it
    if [[ "$(pwd)" == "$wt_path"* ]]; then
      cd "$REPO_ROOT"
    fi
    git -C "$REPO_ROOT" worktree remove --force "$wt_path" 2>/dev/null || true
    echo "[OK] Removed worktree: $wt_path"
  fi

  # Remove local branch if it was never pushed
  if [ -n "$branch" ]; then
    local has_remote
    has_remote="$(git -C "$REPO_ROOT" branch -r --list "origin/$branch" 2>/dev/null)"
    if [ -z "$has_remote" ]; then
      git -C "$REPO_ROOT" branch -D "$branch" 2>/dev/null || true
      echo "[OK] Removed unpushed branch: $branch"
    else
      echo "[INFO] Branch $branch has remote tracking; kept."
    fi
  fi

  echo "[SUCCESS] Session $session_id cleaned up."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
MODE="${1:-}"

if [ -z "$MODE" ]; then
  echo "Usage: $0 <session-id> | --self | --stale"
  exit 1
fi

if [ "$MODE" = "--stale" ]; then
  echo "[INFO] Cleaning stale sessions (dead PIDs)..."
  cleaned=0
  for lockfile in "$LOCK_DIR"/*.lock; do
    [ -f "$lockfile" ] || continue
    pid="$(grep '^pid=' "$lockfile" | cut -d= -f2)"
    if ! kill -0 "$pid" 2>/dev/null; then
      cleanup_session "$lockfile"
      cleaned=$((cleaned + 1))
    fi
  done
  echo "[DONE] Cleaned $cleaned stale session(s)."
  exit 0
fi

if [ "$MODE" = "--self" ]; then
  # Find lock file matching current PID
  found=""
  for lockfile in "$LOCK_DIR"/*.lock; do
    [ -f "$lockfile" ] || continue
    pid="$(grep '^pid=' "$lockfile" | cut -d= -f2)"
    if [ "$pid" = "$$" ]; then
      found="$lockfile"
      break
    fi
  done
  if [ -z "$found" ]; then
    echo "[INFO] No lock file found for PID $$. Nothing to clean."
    exit 0
  fi
  cleanup_session "$found"
  exit 0
fi

# Treat argument as session-id
LOCKFILE="$LOCK_DIR/$MODE.lock"
if [ ! -f "$LOCKFILE" ]; then
  echo "[WARN] No lock file found for session '$MODE'."
  # Still try to remove worktree directory if it exists
  WT="$WORKTREE_DIR/$MODE"
  if [ -d "$WT" ]; then
    git -C "$REPO_ROOT" worktree remove --force "$WT" 2>/dev/null || true
    echo "[OK] Removed orphaned worktree: $WT"
  fi
  exit 0
fi

cleanup_session "$LOCKFILE"
