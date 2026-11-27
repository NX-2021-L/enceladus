#!/usr/bin/env bash
# agent-lock.sh — reading agent worktree lock files, tolerantly.
#
# ENC-TSK-T28. Sourced by tools/agent-worktree-init.sh and exercised directly by
# tools/lib/agent-lock.selftest.sh. Pure functions only: nothing here writes,
# removes or mutates anything, which is deliberate — the caller decides what to
# do with a classification, and the destructive path lives there under the
# ENC-ISS-632 gates.
#
# WHY THIS EXISTS. agent-worktree-init.sh runs under `set -euo pipefail` and read
# its lock fields with bare command substitutions:
#
#     LOCK_PID="$(grep '^pid=' "$lockfile" | cut -d= -f2)"
#
# `grep` exits 1 when it matches nothing. Under `pipefail` the pipeline fails,
# the command substitution in the assignment propagates that, and `set -e` kills
# the script. So a SINGLE lock file not in key=value form aborted the whole
# invocation before it reached "[INFO] Fetching origin..." — no worktree, exit 1,
# and nothing but the preceding warnings on stdout to explain it. This repository
# has carried three such files since August 2026, which means step 0.2 of the
# documented session bootstrap had been failing for every session:
#
#     enc-tsk-p58-record-routing.lock   ENC-SES-0G0 2026-08-27T03:38:25Z
#     enc-tsk-p53-legacy-sunset.lock    {"task":"ENC-TSK-P53","created":"..."}
#     enc-tsk-p66-neighbors-distance-order.lock  {"task":...,"session":...}
#
# One field had already been patched for this (`branch=` carries `|| true`),
# which is the tell that someone hit the same wall and fixed only the line in
# front of them.

# Read one key=value field from a lock file.
#
# Prints the value, or nothing when the key is absent, the file is unreadable or
# the file is not in key=value form at all. NEVER fails, so it is safe on the
# right-hand side of an assignment under `set -e`. The trailing `|| true` is the
# whole point and must not be removed.
#
# Takes the FIRST match, so a duplicated key cannot produce a multi-line value
# that would later be word-split into a surprise.
agent_lock_field() {
  local file="$1" key="$2"
  [ -r "$file" ] || return 0
  sed -n "s/^${key}=//p" "$file" 2>/dev/null | head -n 1 || true
}

# Classify a lock file as live, dead or unknown. Prints exactly one word.
#
#   live     the recorded pid is a positive integer and a signalable process.
#            The owning session is (or may be) working: leave it entirely alone.
#   dead     the recorded pid is a positive integer and no such process answers.
#            Eligible for the caller's ENC-ISS-632 sweep gates.
#   unknown  there is no usable pid: the file is empty, has no `pid=` line, or
#            the value is not a positive integer. We cannot say anything about
#            the owning session.
#
# `unknown` is NEVER swept by the caller, and that asymmetry is deliberate. The
# sweep force-removes a worktree and deletes an unpushed branch; ENC-ISS-632 is
# the record of it destroying three worktrees and two sibling branches when the
# pid signal was trusted too readily. An unparseable lock is precisely the case
# where we know least about who owns it, so it gets the most conservative
# treatment: report it, touch nothing, and let a human decide.
#
# `pid=0` is the reason this is three-valued rather than a boolean. `kill -0 0`
# signals the CALLER'S OWN PROCESS GROUP and therefore succeeds, so a lock
# recording pid 0 looked like a live session forever — which is exactly what the
# three legacy files above did, reporting as "Active session: ... (PID 0)" on
# every run since August while never being swept. 0 is not a user process id, so
# it is treated as no information rather than as proof of life.
agent_lock_classify() {
  local file="$1" pid
  pid="$(agent_lock_field "$file" pid)"

  # Positive integer only: rejects empty, 0, negatives, "unknown", JSON, floats.
  case "$pid" in
    '' | *[!0-9]*) echo unknown; return 0 ;;
  esac
  [ "$pid" -gt 0 ] 2>/dev/null || { echo unknown; return 0; }

  if kill -0 "$pid" 2>/dev/null; then
    echo live
  else
    echo dead
  fi
}
