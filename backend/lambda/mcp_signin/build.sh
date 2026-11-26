#!/usr/bin/env bash
# Builds mcp_signin.zip (pure JS, arm64-safe) for ENC-TSK-S57-a.
# Needs CODEARTIFACT_AUTH_TOKEN for @io-kit (see .npmrc; the token is never written to disk by this script).
# Fleet registry: @io-kit/mcp 0.3.x ships none (ENC-ISS-919). The handler reads build/fleet.json at cold start, taken from
#   IO_KIT_FLEET_JSON (inline JSON) > IO_KIT_FLEET_FILE (a path) > fleet.enceladus.json (the committed enceladus registry).
set -euo pipefail
: "${CODEARTIFACT_AUTH_TOKEN:?CODEARTIFACT_AUTH_TOKEN is empty: see .npmrc for the login command}"
cd "$(dirname "$0")"
rm -rf build mcp_signin.zip && mkdir build
cp index.mjs config.mjs package.json .npmrc build/
( cd build && npm install --omit=dev --ignore-scripts --no-audit --no-fund --no-package-lock )
if [ -n "${IO_KIT_FLEET_JSON:-}" ]; then
  printf '%s\n' "$IO_KIT_FLEET_JSON" > build/fleet.json
elif [ -n "${IO_KIT_FLEET_FILE:-}" ]; then
  cp "$IO_KIT_FLEET_FILE" build/fleet.json
else
  cp fleet.enceladus.json build/fleet.json
fi
node -e '
const f = JSON.parse(require("fs").readFileSync("build/fleet.json", "utf8"));
if (!(f.connectors || []).some((c) => c.profile === "enceladus")) { console.error("fleet.json has no enceladus connector"); process.exit(1); }
const v = require("./build/node_modules/@io-kit/mcp/package.json").version;
if (v !== "0.3.1") { console.error("expected @io-kit/mcp 0.3.1, got " + v); process.exit(1); }
'
rm -f build/.npmrc
( cd build && zip -qr ../mcp_signin.zip . )
echo "built $(pwd)/mcp_signin.zip"
