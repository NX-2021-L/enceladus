#!/usr/bin/env bash
# Gamma deploy->validate->promote gate — ENC-TSK-H58 (code child ENC-TSK-H69).
#
# Fail-closed RUNTIME validation of the live gamma pre-prod environment, run AFTER
# a gamma deploy and BEFORE prod promotion. A green run makes prod promotion
# AVAILABLE (the caller dispatches promote-gamma-to-prod-request.yml, which then
# pauses on the v3-prod required-reviewer gate for a HUMAN to approve). A red run
# blocks promotion. This is the gamma analog of tools/pre-deploy-health-gate.sh,
# but it probes the LIVE deployed environment instead of a template.
#
# Bound to ENC-LSN-039 (pre-probe gamma before prod handoffs) and
# DOC-733D76F4849B L1 (observability precedes deployability). It is the validation
# step the api-stack deploy path lacks (ENC-TSK-H64 finding).
#
# Checks (ALL must pass — fail-closed):
#   1. WARM   — invoke the on-demand standing-projection refresh on
#               devops-graph-query-api-gamma (gamma has no always-warm AGA session,
#               per the ENC-PLN-050 cost model, so the gds_standing projection is
#               cold between runs). BEST-EFFORT: the refresh response's `ok` flag is
#               a known FALSE-NEGATIVE on a cold AGA session (gds.graph.drop raises
#               "graph ... might exist on another database"), so we DO NOT gate on it
#               — we gate on the actual hybrid query in check 3 (ENC-TSK-H58 finding).
#   2. SMOKE  — gamma API ingress serves: capabilities == 200 AND graphsearch/health
#               == 200 with graph_index status == healthy.
#   3. GRAPH  — hybrid graphsearch signal check (two modes):
#               GDS configured (GDS_STANDING_PROJECTION_PREFIX set in gamma Lambda):
#                 must return graph_algorithm == gds_pagerank AND full trio
#                 {vector, graph, keyword} all true.
#               GDS not configured (prefix unset — e.g. during ENC-ISS-197 compute
#                 stack freeze): must return success == true AND vector AND keyword
#                 (graph signal may timeout; accepted when GDS is off). Gate reads
#                 graph_index.graph_projection.configured from graphsearch/health.
#   4. PARITY — tools/env_parity_gate.py is green on the gamma compute param set
#               (no deploy-critical env var the next gamma compute deploy would strip).
#
# Usage:
#   COORDINATION_INTERNAL_API_KEY=<key> bash tools/gamma_validation_gate.sh
#
# Options:
#   --skip-warm        Skip check 1 (used to PROVE fail-closed: a cold projection
#                      makes check 3 fall back off gds_pagerank -> gate RED).
#   --api-id <id>      Gamma tracker API id          (default: hi0dzmvqrc)
#   --graph-fn <name>  Gamma graph-query Lambda name (default: devops-graph-query-api-gamma)
#   --template <path>  Compute template for env-parity (default: infrastructure/cloudformation/02-compute.yaml)
#   --region <region>  AWS region                    (default: us-west-2 / AWS_DEFAULT_REGION)
#
# Exit codes: 0 = GREEN (promotion available), 1 = RED (promotion blocked).

set -uo pipefail  # deliberately NOT -e: run all checks, then aggregate fail-closed.

REGION="${AWS_DEFAULT_REGION:-us-west-2}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GAMMA_API_ID="hi0dzmvqrc"
GAMMA_GRAPH_FN="devops-graph-query-api-gamma"
TEMPLATE_FILE="infrastructure/cloudformation/02-compute.yaml"
SKIP_WARM=false
PROJECT="enceladus"
ANCHOR="${GAMMA_GATE_ANCHOR:-ENC-FTR-062}"          # a stable gamma feature node to anchor PPR
QUERY="${GAMMA_GATE_QUERY:-extended mind governance}"
GRAPH_PROBE_TIMEOUT="${GRAPH_PROBE_TIMEOUT:-120}"   # AGA warm-projection build latency budget (s)

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-warm) SKIP_WARM=true; shift ;;
        --api-id) GAMMA_API_ID="$2"; shift 2 ;;
        --graph-fn) GAMMA_GRAPH_FN="$2"; shift 2 ;;
        --template) TEMPLATE_FILE="$2"; shift 2 ;;
        --region) REGION="$2"; shift 2 ;;
        -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
        *) echo "[ERROR] unknown argument: $1" >&2; exit 1 ;;
    esac
done

[[ "$TEMPLATE_FILE" = /* ]] || TEMPLATE_FILE="${REPO_ROOT}/${TEMPLATE_FILE}"
BASE="https://${GAMMA_API_ID}.execute-api.${REGION}.amazonaws.com"
ERRORS=0
PASSES=0

note()  { echo "  $*"; }
pass()  { echo "[PASS] $*"; PASSES=$((PASSES + 1)); }
fail()  { echo "[FAIL] $*"; ERRORS=$((ERRORS + 1)); }

echo "============================================================"
echo "  GAMMA VALIDATION GATE — runtime pre-prod gate (ENC-TSK-H58)"
echo "  api=${GAMMA_API_ID}  graph_fn=${GAMMA_GRAPH_FN}  region=${REGION}"
echo "  skip_warm=${SKIP_WARM}  (a red gate BLOCKS prod promotion)"
echo "============================================================"

# --- Check 1: WARM the on-demand gamma standing projection (best-effort) -------
echo ""
echo "[CHECK 1/4] Warming the on-demand gamma standing projection..."
if [[ "$SKIP_WARM" == "true" ]]; then
    note "--skip-warm set: NOT warming (fail-closed demonstration mode)."
else
    # ASYNC (--invocation-type Event): the AGA projection build is slow (~30-90s) and
    # synchronous invoke would block the gate. Fire-and-forget the refresh, then check 3
    # polls the live hybrid query until the projection is warm (or the budget expires).
    REFRESH_OUT="$(mktemp)"
    if aws lambda invoke --function-name "$GAMMA_GRAPH_FN" --region "$REGION" \
            --invocation-type Event \
            --cli-binary-format raw-in-base64-out \
            --payload "{\"action\":\"refresh_projection\",\"project_ids\":[\"${PROJECT}\"]}" \
            "$REFRESH_OUT" >/dev/null 2>&1; then
        note "refresh dispatched async (202) — projection warming in the background."
        note "(refresh.ok is a known false-negative on cold AGA — check 3 is the real graph gate.)"
    else
        note "refresh dispatch errored (best-effort) — check 3 still governs the graph signal."
    fi
    rm -f "$REFRESH_OUT"
fi

# --- Check 2: SMOKE — ingress serves -------------------------------------------
echo ""
echo "[CHECK 2/4] Smoke — gamma ingress (capabilities + graphsearch/health)..."
CAP_CODE="$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/api/v1/coordination/capabilities" 2>/dev/null || echo 000)"
HEALTH_BODY="$(curl -s "${BASE}/api/v1/tracker/graphsearch/health" 2>/dev/null || echo '{}')"
HEALTH_STATUS="$(echo "$HEALTH_BODY" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("status","?"))' 2>/dev/null || echo '?')"
# Detect whether the gamma Lambda has GDS standing projections configured.
# graph_query_api /health embeds graph_index.graph_projection.configured = bool(GDS_STANDING_PROJECTION_PREFIX).
# When the compute stack is frozen (ENC-ISS-197) the prefix may be absent from gamma's env;
# check 3 uses a relaxed graph criterion in that case.
GDS_CONFIGURED="$(echo "$HEALTH_BODY" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    gi = d.get("graph_index") or {}
    gp = gi.get("graph_projection") or {}
    print("true" if gp.get("configured") else "false")
except Exception:
    print("unknown")
' 2>/dev/null || echo 'unknown')"
if [[ "$CAP_CODE" == "200" && "$HEALTH_STATUS" == "healthy" ]]; then
    pass "smoke: capabilities=200, graphsearch/health status=healthy (gds_configured=${GDS_CONFIGURED})"
else
    fail "smoke: capabilities=${CAP_CODE} (want 200), graphsearch/health status=${HEALTH_STATUS} (want healthy)"
fi

# --- Check 3: GRAPH — hybrid signal probe (mode adapts to GDS configuration) ---
echo ""
if [[ "$GDS_CONFIGURED" == "true" ]]; then
    echo "[CHECK 3/4] Graph-probe (GDS mode) — must return graph_algorithm=gds_pagerank + full trio..."
else
    echo "[CHECK 3/4] Graph-probe (no-GDS mode, gds_configured=${GDS_CONFIGURED}) — must return success=true + vector + keyword..."
    note "GDS_STANDING_PROJECTION_PREFIX absent in gamma Lambda — graph signal timeout is expected."
    note "Strict gds_pagerank requirement deferred until GDS env var is provisioned (ENC-ISS-197)."
fi
if [[ -z "${COORDINATION_INTERNAL_API_KEY:-}" ]]; then
    fail "graph-probe: COORDINATION_INTERNAL_API_KEY not set (required to authenticate the hybrid probe)"
else
    Q="$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "$QUERY")"
    URL="${BASE}/api/v1/tracker/graphsearch?project_id=${PROJECT}&search_type=hybrid&query=${Q}&anchor_record_id=${ANCHOR}&top_n=5"
    DEADLINE=$(( $(date +%s) + GRAPH_PROBE_TIMEOUT ))
    GRAPH_OK=false
    LAST=""
    while [[ $(date +%s) -lt $DEADLINE ]]; do
        BODY="$(curl -s -H "x-coordination-internal-key: ${COORDINATION_INTERNAL_API_KEY}" "$URL" 2>/dev/null || echo '{}')"
        # Single parse -> "ALGO|VEC|KWD|GRP|SUCCESS" (no backslashes — py<3.12 safe).
        PARSED="$(printf '%s' "$BODY" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    print("PARSE_ERR|N|N|N|False"); sys.exit()
sa = d.get("signal_availability") or {}
vec = "Y" if sa.get("vector") else "N"
kwd = "Y" if sa.get("keyword") else "N"
grp = "Y" if sa.get("graph") else "N"
print("%s|%s|%s|%s|%s" % (d.get("graph_algorithm"), vec, kwd, grp, d.get("success")))
' 2>/dev/null || echo "PARSE_ERR|N|N|N|False")"
        ALGO="${PARSED%%|*}"; _rest="${PARSED#*|}"
        VEC="${_rest%%|*}";  _rest="${_rest#*|}"
        KWD="${_rest%%|*}";  _rest="${_rest#*|}"
        GRP="${_rest%%|*}";  SUCCESS="${_rest##*|}"
        LAST="algo=${ALGO} vec=${VEC} kwd=${KWD} graph=${GRP} success=${SUCCESS}"
        if [[ "$GDS_CONFIGURED" == "true" ]]; then
            # Strict: gds_pagerank + all three signals.
            TRIO="N"; [[ "$VEC" == "Y" && "$KWD" == "Y" && "$GRP" == "Y" ]] && TRIO="Y"
            if [[ "$ALGO" == "gds_pagerank" && "$TRIO" == "Y" ]]; then GRAPH_OK=true; break; fi
        else
            # Relaxed: vector + keyword must work; graph timeout is expected without GDS.
            if [[ "$SUCCESS" == "True" && "$VEC" == "Y" && "$KWD" == "Y" ]]; then GRAPH_OK=true; break; fi
        fi
        note "graph signal not yet ready (${LAST}) — retrying..."
        sleep 10
    done
    if [[ "$GRAPH_OK" == "true" ]]; then
        pass "graph-probe: $LAST"
    else
        if [[ "$GDS_CONFIGURED" == "true" ]]; then
            fail "graph-probe: never reached gds_pagerank+full-trio within ${GRAPH_PROBE_TIMEOUT}s (last: $LAST)"
        else
            fail "graph-probe: never reached success+vector+keyword within ${GRAPH_PROBE_TIMEOUT}s (last: $LAST)"
        fi
    fi
fi

# --- Check 4: ENV-PARITY — gamma compute param set -----------------------------
echo ""
echo "[CHECK 4/4] Env-parity — no deploy-critical gamma var the next compute deploy would strip..."
if python3 "${REPO_ROOT}/tools/env_parity_gate.py" \
        --template "$TEMPLATE_FILE" \
        --parameter "EnvironmentSuffix=-gamma" >/dev/null 2>&1; then
    pass "env-parity: gamma compute env is template-codified (no strip-class gaps)"
else
    fail "env-parity: env_parity_gate.py found deploy-critical gamma var(s) the deploy would strip (run it directly for detail)"
fi

# --- Verdict -------------------------------------------------------------------
echo ""
echo "============================================================"
if [[ "$ERRORS" -eq 0 ]]; then
    echo "  GAMMA GATE: GREEN (${PASSES}/3 checks passed) — prod promotion AVAILABLE."
    echo "  (Promotion still pauses on the v3-prod required-reviewer gate — human approves.)"
    echo "============================================================"
    exit 0
else
    echo "  GAMMA GATE: RED (${ERRORS} check(s) failed) — prod promotion BLOCKED."
    echo "============================================================"
    exit 1
fi
