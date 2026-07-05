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
# --allowerasing: AL2023's curl-minimal conflicts with the full curl package.
dnf install -y --allowerasing java-17-amazon-corretto-headless tar gzip curl jq amazon-cloudwatch-agent

if ! id "${OPENSEARCH_USER}" &>/dev/null; then
  useradd --system --home-dir "${OPENSEARCH_HOME}" --shell /sbin/nologin "${OPENSEARCH_USER}"
fi

install -d -m 0755 "${OPENSEARCH_HOME}"
install -d -m 0750 -o "${OPENSEARCH_USER}" -g "${OPENSEARCH_USER}" /var/lib/opensearch
install -d -m 0750 -o "${OPENSEARCH_USER}" -g "${OPENSEARCH_USER}" /var/log/opensearch

TARBALL="opensearch-${OPENSEARCH_VERSION}-linux-arm64.tar.gz"
URL="https://artifacts.opensearch.org/releases/bundle/opensearch/${OPENSEARCH_VERSION}/${TARBALL}"
# /tmp is tmpfs (~924MB on t4g.small), too small for the >1GB extracted tree; use /var/tmp (real EBS).
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
# Do NOT add any plugins.security.* key here: the demo installer's presence
# check (ENC-TSK-L70) treats ANY such key as "already configured" and skips
# TLS cert generation. Security is on by default; no explicit key needed.
CFG="${OPENSEARCH_HOME}/config/opensearch.yml"
TLS_NODE_PEM="${OPENSEARCH_HOME}/config/esnode.pem"
# Failed prior boots can leave plugins.security.disabled on the EBS volume;
# strip it so the demo installer actually regenerates TLS material on retry.
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
# Must run as the unprivileged opensearch user (OpenSearch refuses root).
# --preserve-environment carries OPENSEARCH_INITIAL_ADMIN_PASSWORD. The script
# execs into the OpenSearch server itself once certs are generated (L71) and
# never returns, so background it and poll for the cert instead of waiting.
runuser -u "${OPENSEARCH_USER}" --preserve-environment -- ./opensearch-tar-install.sh &
INSTALLER_PID=$!
for i in $(seq 1 60); do
  if [[ -f "${TLS_NODE_PEM}" ]]; then
    break
  fi
  sleep 5
done
# Superseded by the systemd unit below; ensure clean handoff.
kill "${INSTALLER_PID}" 2>/dev/null || true
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

# ENC-TSK-L44 audit logging: via opensearch.yml post-bootstrap (not the demo
# installer path, per the L70 guard above); needs a restart to take effect.
if ! grep -q 'ENC-TSK-L44 audit' "${CFG}"; then
  log "Enabling security-plugin audit logging"
  cat >> "${CFG}" <<EOF

########## ENC-TSK-L44 audit ##########
plugins.security.audit.type: internal_opensearch
plugins.security.audit.config.disabled_rest_categories: NONE
plugins.security.audit.config.disabled_transport_categories: NONE
########## END ENC-TSK-L44 audit ##########
EOF
  systemctl restart opensearch
  log "Waiting for cluster health GREEN after audit-log restart"
  for i in $(seq 1 60); do
    if curl -ks -u "admin:${ADMIN_PASSWORD}" "https://127.0.0.1:9200/_cluster/health" \
      | jq -e '.status == "green" or .status == "yellow"' >/dev/null 2>&1; then
      break
    fi
    sleep 5
  done
else
  log "ENC-TSK-L44 audit config already present; skipping restart"
fi

# ENC-TSK-L44 fine-grained roles + Secrets Manager rotation; idempotent re-run.
log "Provisioning fine-grained security roles + Secrets Manager credentials"

AWS_REGION_RESOLVED="${AWS_REGION:-$(curl -fsS -m 2 http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null || echo us-west-2)}"
SECRET_PREFIX="${OPENSEARCH_SECRET_PREFIX:-enceladus/opensearch}"
SECRET_ENV="${OPENSEARCH_SECRET_ENV:-gamma}"

if ! command -v aws &>/dev/null; then
  dnf install -y awscli || pip3 install --quiet awscli
fi

_put_secret() {
  local username="$1" password="$2"
  local secret_id="${SECRET_PREFIX}/${SECRET_ENV}-${username}"
  local payload
  payload="$(jq -n --arg u "${username}" --arg p "${password}" '{username:$u, password:$p}')"
  if aws secretsmanager describe-secret --secret-id "${secret_id}" --region "${AWS_REGION_RESOLVED}" >/dev/null 2>&1; then
    aws secretsmanager put-secret-value --secret-id "${secret_id}" --secret-string "${payload}" --region "${AWS_REGION_RESOLVED}" >/dev/null
  else
    aws secretsmanager create-secret --name "${secret_id}" --secret-string "${payload}" --region "${AWS_REGION_RESOLVED}" >/dev/null
  fi
  log "Secrets Manager: synced ${secret_id}"
}

_put_secret "admin" "${ADMIN_PASSWORD}"

INDEXER_PASSWORD_FILE="/root/.opensearch-indexer-password"
QUERY_PASSWORD_FILE="/root/.opensearch-query-password"
if [[ ! -f "${INDEXER_PASSWORD_FILE}" ]]; then
  openssl rand -base64 24 > "${INDEXER_PASSWORD_FILE}"
  chmod 0600 "${INDEXER_PASSWORD_FILE}"
fi
if [[ ! -f "${QUERY_PASSWORD_FILE}" ]]; then
  openssl rand -base64 24 > "${QUERY_PASSWORD_FILE}"
  chmod 0600 "${QUERY_PASSWORD_FILE}"
fi
INDEXER_PASSWORD="$(tr -d '\n' < "${INDEXER_PASSWORD_FILE}")"
QUERY_PASSWORD="$(tr -d '\n' < "${QUERY_PASSWORD_FILE}")"

_put_secret "indexer" "${INDEXER_PASSWORD}"
_put_secret "query" "${QUERY_PASSWORD}"

log "Applying indexer_role / query_role via Security REST API"
SEC="https://127.0.0.1:9200/_plugins/_security/api"
_sec_put() { curl -ks -u "admin:${ADMIN_PASSWORD}" -X PUT "${SEC}/$1" -H 'Content-Type: application/json' -d "$2"; }
_sec_put "roles/indexer_role" '{"cluster_permissions":["cluster_composite_ops","cluster:monitor/*"],"index_permissions":[{"index_patterns":["records_write","records_v*"],"allowed_actions":["indices:data/write/*","indices:admin/create","indices:admin/mapping/put","indices:admin/aliases","indices:monitor/*"]}]}'
_sec_put "roles/query_role" '{"cluster_permissions":["cluster:monitor/*"],"index_permissions":[{"index_patterns":["records_read","records_v*"],"allowed_actions":["indices:data/read/*","indices:monitor/*"]}]}'
_sec_put "internalusers/indexer" "$(jq -n --arg p "${INDEXER_PASSWORD}" '{password:$p, backend_roles:["indexer_backend"], description:"L44 write-only"}')"
_sec_put "internalusers/query" "$(jq -n --arg p "${QUERY_PASSWORD}" '{password:$p, backend_roles:["query_backend"], description:"L44 read-only"}')"
_sec_put "rolesmapping/indexer_role" '{"backend_roles":["indexer_backend"],"users":["indexer"]}'
_sec_put "rolesmapping/query_role" '{"backend_roles":["query_backend"],"users":["query"]}'

# ENC-TSK-L45 monitoring (AC-1): disk via CW Agent; JVM heap has no native
# metric, pushed by a cron polling OpenSearch's own stats API instead.
log "Configuring CloudWatch Agent + JVM heap heartbeat cron"
CW_NAMESPACE="Enceladus/OpenSearch"
mkdir -p /opt/aws/amazon-cloudwatch-agent/etc
cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json <<EOF
{"metrics":{"namespace":"${CW_NAMESPACE}","append_dimensions":{"InstanceId":"\${aws:InstanceId}"},"aggregation_dimensions":[["InstanceId","path"],["InstanceId"]],"metrics_collected":{"disk":{"measurement":["used_percent"],"resources":["/"],"ignore_file_system_types":["sysfs","devtmpfs","tmpfs"],"drop_device":true},"mem":{"measurement":["mem_used_percent"]},"procstat":[{"pattern":"opensearch","measurement":["cpu_usage","memory_rss"]}]}}}
EOF
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json

cat > /usr/local/bin/opensearch-jvm-heartbeat.sh <<'HEARTBEAT'
#!/usr/bin/env bash
set -euo pipefail
ADMIN_PASSWORD_FILE="${OPENSEARCH_ADMIN_PASSWORD_FILE:-/root/.opensearch-admin-password}"
NAMESPACE="${CW_NAMESPACE:-Enceladus/OpenSearch}"
REGION="$(curl -fsS -m 2 http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null || echo us-west-2)"
IID="$(curl -fsS -m 2 http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo unknown)"
PW="$(tr -d '\n' < "${ADMIN_PASSWORD_FILE}" 2>/dev/null || true)"
[[ -z "${PW}" ]] && exit 0
STATS="$(curl -ks -m 5 -u "admin:${PW}" "https://127.0.0.1:9200/_nodes/stats/jvm" 2>/dev/null || true)"
if [[ -z "${STATS}" ]]; then
  # unreachable: push NodeUp=0 (not a JVMHeapPercent point -- missing data, not a false zero)
  aws cloudwatch put-metric-data --region "${REGION}" --namespace "${NAMESPACE}" --metric-data "MetricName=NodeUp,Value=0,Unit=Count,Dimensions=[{Name=InstanceId,Value=${IID}}]"
  exit 0
fi
HEAP="$(echo "${STATS}" | jq -r '.nodes | to_entries[0].value.jvm.mem.heap_used_percent // empty')"
aws cloudwatch put-metric-data --region "${REGION}" --namespace "${NAMESPACE}" --metric-data "MetricName=NodeUp,Value=1,Unit=Count,Dimensions=[{Name=InstanceId,Value=${IID}}]"
[[ -n "${HEAP}" ]] && aws cloudwatch put-metric-data --region "${REGION}" --namespace "${NAMESPACE}" --metric-data "MetricName=JVMHeapPercent,Value=${HEAP},Unit=Percent,Dimensions=[{Name=InstanceId,Value=${IID}}]"
HEARTBEAT
chmod +x /usr/local/bin/opensearch-jvm-heartbeat.sh

cat > /etc/cron.d/opensearch-jvm-heartbeat <<EOF
* * * * * root CW_NAMESPACE="${CW_NAMESPACE}" /usr/local/bin/opensearch-jvm-heartbeat.sh >> /var/log/opensearch-jvm-heartbeat.log 2>&1
EOF
chmod 0644 /etc/cron.d/opensearch-jvm-heartbeat

touch "${MARKER}"
log "Bootstrap complete"
