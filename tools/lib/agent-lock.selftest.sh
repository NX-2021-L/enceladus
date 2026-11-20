#!/usr/bin/env bash
# agent-lock.selftest.sh — ENC-TSK-T28. Exercises tools/lib/agent-lock.sh.
#
# Run: bash tools/lib/agent-lock.selftest.sh
# Exit 0 on pass, 1 on any failure. No arguments, no network, no repo writes:
# everything happens in a temp dir that is removed on exit.
#
# Runs under the SAME `set -euo pipefail` as agent-worktree-init.sh, because the
# bug being pinned was a `set -e` abort rather than a wrong answer. A regression
# that reintroduced a bare `grep` would kill this script, and that is the point:
# the harness has to be as unforgiving as the caller.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tools/lib/agent-lock.sh
. "$HERE/agent-lock.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0

check() {
  local name="$1" want="$2" got="$3"
  if [ "$want" = "$got" ]; then
    PASS=$((PASS + 1))
    printf '  ok   %-58s %s\n' "$name" "$got"
  else
    FAIL=$((FAIL + 1))
    printf '  FAIL %-58s want=%s got=%s\n' "$name" "$want" "$got"
  fi
}

# A pid that is certainly not running: start a process, wait for it to exit.
# Reusing the number within the same second is vanishingly unlikely, and far
# safer than guessing a value above pid_max, which differs per platform.
sh -c 'exit 0' & DEAD_PID=$!
wait "$DEAD_PID" 2>/dev/null || true

wellformed() {
  cat > "$TMP/$1" <<EOF
pid=$2
provider=ENC-SES-TEST
started=2026-11-20T00:00:00Z
worktree=$TMP/wt-$1
branch=agent/$1
task_id=$1
EOF
}

echo "agent_lock_classify:"

wellformed live.lock "$$"
check "live: pid is this very process"            live    "$(agent_lock_classify "$TMP/live.lock")"

wellformed dead.lock "$DEAD_PID"
check "dead: pid exited moments ago"              dead    "$(agent_lock_classify "$TMP/dead.lock")"

# The three shapes actually present in this repository since August 2026.
wellformed zero.lock 0
check "unknown: pid=0 (kill -0 0 hits our group)" unknown "$(agent_lock_classify "$TMP/zero.lock")"

printf 'ENC-SES-0G0 2026-08-27T03:38:25Z\n' > "$TMP/bare.lock"
check "unknown: bare 'SESSION TIMESTAMP' line"    unknown "$(agent_lock_classify "$TMP/bare.lock")"

printf '{"task":"ENC-TSK-P53","created":"2026-08-27T16:29:23Z"}\n' > "$TMP/json.lock"
check "unknown: JSON object"                      unknown "$(agent_lock_classify "$TMP/json.lock")"

# Other ways a lock file can be useless.
printf 'provider=ENC-SES-X\nbranch=agent/x\n' > "$TMP/nopid.lock"
check "unknown: key=value but no pid line"        unknown "$(agent_lock_classify "$TMP/nopid.lock")"

: > "$TMP/empty.lock"
check "unknown: empty file"                       unknown "$(agent_lock_classify "$TMP/empty.lock")"

wellformed notnum.lock "not-a-number"
check "unknown: non-numeric pid"                  unknown "$(agent_lock_classify "$TMP/notnum.lock")"

wellformed negative.lock "-1"
check "unknown: negative pid"                     unknown "$(agent_lock_classify "$TMP/negative.lock")"

check "unknown: file does not exist"              unknown "$(agent_lock_classify "$TMP/absent.lock")"

echo "agent_lock_field:"

check "field: reads provider"        "ENC-SES-TEST" "$(agent_lock_field "$TMP/live.lock" provider)"
check "field: absent key is empty"   ""             "$(agent_lock_field "$TMP/live.lock" nosuchkey)"
check "field: malformed file is empty" ""           "$(agent_lock_field "$TMP/json.lock" pid)"
check "field: missing file is empty" ""             "$(agent_lock_field "$TMP/absent.lock" provider)"

# A duplicated key must yield ONE value, not a two-line string that would be
# word-split into a surprise by an unquoted expansion downstream.
printf 'pid=111\npid=222\n' > "$TMP/dup.lock"
check "field: duplicate key takes the first"       "111" "$(agent_lock_field "$TMP/dup.lock" pid)"

echo
echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ]
