#!/usr/bin/env bash
# ENC-TSK-L39 — single-node OpenSearch bootstrap for gamma (t4g.small / arm64).
# Installed by 10-opensearch-node.yaml UserData. Idempotent on re-run except first
# cluster formation (guarded by marker file).
set -euo pipefail

exec > /var/log/opensearch-bootstrap.log 2>&1

OPENSEARCH_VERSION="${OPENSEARCH_VERSION:-2.19.1}"
OPENSEARCH_HOME="${OPENSEARCH_HOME:-/usr/share/opensearch}"
OPENSEARCH_USER="${OPENSEARCH_USER:-opensearch}"
CLUSTER_NAME="${OPENSEARCH_CLUSTER_NAME:-enceladus-search-gamma}"
NODE_NAME="${OPENSEARCH_NODE_NAME:-search-node-1}"
ADMIN_PASSWORD_FILE="${OPENSEARCH_ADMIN_PASSWORD_FILE:-/root/.opensearch-admin-password}"
MARKER="/var/lib/opensearch/.bootstrap-complete"
JVM_HEAP="${OPENSEARCH_JVM_HEAP:-1g}"

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

if [[ -f "${MARKER}" ]]; then
  log "Bootstrap already complete; exiting."
  exit 0
fi

log "Installing prerequisites"
# --allowerasing: AL2023 preinstalls curl-minimal, which conflicts with the full
# curl package on package name; let dnf swap it in (ENC-TSK-L39 bootstrap bug).
dnf install -y --allowerasing java-17-amazon-corretto-headless tar gzip curl jq amazon-cloudwatch-agent

if ! id "${OPENSEARCH_USER}" &>/dev/null; then
  useradd --system --home-dir "${OPENSEARCH_HOME}" --shell /sbin/nologin "${OPENSEARCH_USER}"
fi

install -d -m 0755 "${OPENSEARCH_HOME}"
install -d -m 0750 -o "${OPENSEARCH_USER}" -g "${OPENSEARCH_USER}" /var/lib/opensearch
install -d -m 0750 -o "${OPENSEARCH_USER}" -g "${OPENSEARCH_USER}" /var/log/opensearch

TARBALL="opensearch-${OPENSEARCH_VERSION}-linux-arm64.tar.gz"
URL="https://artifacts.opensearch.org/releases/bundle/opensearch/${OPENSEARCH_VERSION}/${TARBALL}"
# /tmp is tmpfs (RAM-backed, ~50% of instance RAM -- ~924MB on t4g.small), too
# small for the OpenSearch download + extracted tree (>1GB with bundled SQL/ML
# plugins). /var/tmp lives on the real root EBS volume; use it instead.
BUILD_DIR="/var/tmp/opensearch-build"
TMP="${BUILD_DIR}/${TARBALL}"

if [[ ! -x "${OPENSEARCH_HOME}/bin/opensearch" ]]; then
  log "Downloading OpenSearch ${OPENSEARCH_VERSION} (${URL})"
  mkdir -p "${BUILD_DIR}"
  curl -fsSL "${URL}" -o "${TMP}"
  tar -xzf "${TMP}" -C "${BUILD_DIR}"
  rm -rf "${OPENSEARCH_HOME:?}"/*
  cp -a "${BUILD_DIR}/opensearch-${OPENSEARCH_VERSION}"/* "${OPENSEARCH_HOME}/"
  rm -rf "${BUILD_DIR}"
fi

chown -R "${OPENSEARCH_USER}:${OPENSEARCH_USER}" "${OPENSEARCH_HOME}" /var/lib/opensearch /var/log/opensearch

if [[ ! -f "${ADMIN_PASSWORD_FILE}" ]]; then
  openssl rand -base64 24 > "${ADMIN_PASSWORD_FILE}"
  chmod 0600 "${ADMIN_PASSWORD_FILE}"
fi
ADMIN_PASSWORD="$(tr -d '\n' < "${ADMIN_PASSWORD_FILE}")"
export OPENSEARCH_INITIAL_ADMIN_PASSWORD="${ADMIN_PASSWORD}"

log "Writing opensearch.yml"
# Do NOT add any plugins.security.* key here: the demo installer below
# (org.opensearch.security.tools.democonfig.Installer) treats presence of
# any such key as "already configured" and silently quits without
# generating TLS certs (ENC-TSK-L70) -- security is enabled by default,
# so no explicit setting is needed anyway.
CFG="${OPENSEARCH_HOME}/config/opensearch.yml"
TLS_NODE_PEM="${OPENSEARCH_HOME}/config/esnode.pem"
# Failed prior boots (or older bootstrap scripts) can leave
# plugins.security.disabled on the persisted EBS volume; strip so the demo
# installer actually generates demo TLS material on retry.
if [[ ! -f "${TLS_NODE_PEM}" ]]; then
  log "TLS certs missing; stripping stale plugins.security.* keys before demo install"
  sed -i '/^plugins\.security\./d' "${CFG}"
fi
if ! grep -q 'ENC-TSK-L39 generated' "${CFG}"; then
  cat >> "${CFG}" <<EOF

########## ENC-TSK-L39 generated ##########
cluster.name: ${CLUSTER_NAME}
node.name: ${NODE_NAME}
discovery.type: single-node
network.host: 0.0.0.0
path.data: /var/lib/opensearch
path.logs: /var/log/opensearch
action.auto_create_index: true
########## END ENC-TSK-L39 generated ##########
EOF
else
  log "ENC-TSK-L39 opensearch.yml block already present; skipping append"
fi

install -d -m 0755 "${OPENSEARCH_HOME}/config/jvm.options.d"
cat > "${OPENSEARCH_HOME}/config/jvm.options.d/heap.options" <<EOF
-Xms${JVM_HEAP}
-Xmx${JVM_HEAP}
EOF

log "Running opensearch-tar-install.sh (TLS + security plugin demo certs)"
cd "${OPENSEARCH_HOME}"
chmod +x ./opensearch-tar-install.sh
# OpenSearch refuses to start as root ("can not run opensearch as root");
# opensearch-tar-install.sh launches OpenSearch internally to generate the
# demo TLS/security config, so it must run as the unprivileged opensearch
# user. --preserve-environment carries OPENSEARCH_INITIAL_ADMIN_PASSWORD.
runuser -u "${OPENSEARCH_USER}" --preserve-environment -- ./opensearch-tar-install.sh
# Demo installer may leave a foreground process; ensure clean handoff to systemd.
pkill -u "${OPENSEARCH_USER}" || true
sleep 2
if [[ ! -f "${TLS_NODE_PEM}" ]]; then
  log "ERROR: demo installer did not generate TLS certs (${TLS_NODE_PEM} missing)"
  exit 1
fi

log "Installing systemd unit"
cat > /etc/systemd/system/opensearch.service <<EOF
[Unit]
Description=OpenSearch (ENC-TSK-L39 single node)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${OPENSEARCH_USER}
Group=${OPENSEARCH_USER}
Environment=OPENSEARCH_HOME=${OPENSEARCH_HOME}
Environment=OPENSEARCH_PATH_CONF=${OPENSEARCH_HOME}/config
Environment=OPENSEARCH_JAVA_HOME=${OPENSEARCH_HOME}/jdk
WorkingDirectory=${OPENSEARCH_HOME}
ExecStart=${OPENSEARCH_HOME}/bin/opensearch
Restart=on-failure
LimitNOFILE=65536
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable opensearch
systemctl restart opensearch

log "Waiting for cluster health GREEN"
for i in $(seq 1 60); do
  if curl -ks -u "admin:${ADMIN_PASSWORD}" "https://127.0.0.1:9200/_cluster/health" \
    | jq -e '.status == "green" or .status == "yellow"' >/dev/null 2>&1; then
    break
  fi
  sleep 5
done

curl -ks -u "admin:${ADMIN_PASSWORD}" "https://127.0.0.1:9200/_cluster/health?wait_for_status=green&timeout=120s" | tee /var/log/opensearch-cluster-health.json

log "Applying default index template (number_of_replicas: 0)"
curl -ks -u "admin:${ADMIN_PASSWORD}" -X PUT "https://127.0.0.1:9200/_index_template/enceladus-default-replicas-zero" \
  -H 'Content-Type: application/json' \
  -d '{"index_patterns":["enceladus-*"],"template":{"settings":{"number_of_shards":1,"number_of_replicas":0}}}'

touch "${MARKER}"
log "Bootstrap complete"
