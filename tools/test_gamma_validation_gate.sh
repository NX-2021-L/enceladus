#!/usr/bin/env bash
# Hermetic tests for tools/gamma_validation_gate.sh — ENC-TSK-H58 (child ENC-TSK-H69).
#
# No live AWS/network: stubs `aws` + `curl` on PATH and runs the gate inside a temp
# REPO_ROOT whose tools/env_parity_gate.py is a controllable fake. Asserts the
# FAIL-CLOSED contract: GREEN only when every gating check passes; RED (exit 1)
# whenever any one of smoke / graph (gds_pagerank+trio) / env-parity fails.
set -uo pipefail

SRC_GATE="$(cd "$(dirname "$0")" && pwd)/gamma_validation_gate.sh"
FAILS=0

make_sandbox() {
    # $1=dir. Lays out tmp/{bin,tools,infrastructure/cloudformation} + stubs.
    local d="$1"
    mkdir -p "$d/bin" "$d/tools" "$d/infrastructure/cloudformation"
    cp "$SRC_GATE" "$d/tools/gamma_validation_gate.sh"
    : > "$d/infrastructure/cloudformation/02-compute.yaml"

    cat > "$d/bin/aws" <<'EOF'
#!/usr/bin/env bash
# warm-step stub: last arg is the output file; succeed silently.
out="${@: -1}"; [[ "$out" == *.json || -e "$(dirname "$out")" ]] && : > "$out" 2>/dev/null
exit 0
EOF

    cat > "$d/bin/curl" <<'EOF'
#!/usr/bin/env bash
url="${!#}"   # last arg is the URL
case "$url" in
  *"/coordination/capabilities"*) printf '%s' "${GATE_TEST_CAP_CODE:-200}" ;;   # -o /dev/null -w '%{http_code}'
  *"/graphsearch/health"*)        printf '{"status":"%s","signals":{"vector":true,"graph":true,"keyword":true}}' "${GATE_TEST_HEALTH:-healthy}" ;;
  *"search_type=hybrid"*)         printf '{"success":true,"graph_algorithm":"%s","signal_availability":{"vector":%s,"graph":%s,"keyword":%s}}' \
                                    "${GATE_TEST_ALGO:-gds_pagerank}" "${GATE_TEST_V:-true}" "${GATE_TEST_G:-true}" "${GATE_TEST_K:-true}" ;;
  *) printf '{}' ;;
esac
EOF

    cat > "$d/tools/env_parity_gate.py" <<'EOF'
import os, sys
sys.exit(int(os.environ.get("GATE_TEST_PARITY_EXIT", "0")))
EOF
    chmod +x "$d/bin/aws" "$d/bin/curl"
}

run_case() {
    # $1=name  $2=expected_exit  rest=env assignments
    local name="$1" expect="$2"; shift 2
    local d; d="$(mktemp -d)"; make_sandbox "$d"
    local out rc
    out="$(cd "$d" && env PATH="$d/bin:$PATH" COORDINATION_INTERNAL_API_KEY=testkey \
        GRAPH_PROBE_TIMEOUT=2 "$@" bash "$d/tools/gamma_validation_gate.sh" 2>&1)"
    rc=$?
    rm -rf "$d"
    if [[ "$rc" -eq "$expect" ]]; then
        echo "[ok]   $name -> exit $rc (expected $expect)"
    else
        echo "[FAIL] $name -> exit $rc (expected $expect)"
        echo "$out" | sed 's/^/       | /'
        FAILS=$((FAILS + 1))
    fi
}

echo "=== gamma_validation_gate.sh hermetic tests ==="
# All signals healthy -> GREEN.
run_case "all-green"             0
# Graph signal not gds_pagerank (cold/fallback) -> RED (the core fail-closed case).
run_case "graph-not-pagerank"    1  GATE_TEST_ALGO=timeout
# Graph trio incomplete (graph signal down) -> RED.
run_case "graph-trio-broken"     1  GATE_TEST_G=false
# Smoke: capabilities non-200 -> RED.
run_case "smoke-capabilities"    1  GATE_TEST_CAP_CODE=503
# Smoke: health not healthy -> RED.
run_case "smoke-health"          1  GATE_TEST_HEALTH=degraded
# Env-parity gate fails (a deploy-critical var would be stripped) -> RED.
run_case "env-parity-strip"      1  GATE_TEST_PARITY_EXIT=2
# Missing internal key -> graph probe cannot authenticate -> RED.
run_case "missing-key"           1  COORDINATION_INTERNAL_API_KEY=

echo ""
if [[ "$FAILS" -eq 0 ]]; then
    echo "ALL TESTS PASSED"; exit 0
else
    echo "${FAILS} TEST(S) FAILED"; exit 1
fi
