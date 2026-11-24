// Config assembly for the Enceladus kit sign-in service (ENC-TSK-S57-a). No @io-kit import, so it unit-tests offline.
// Everything deployment-specific comes from the environment the stack sets (CONNECT_ORIGIN, AUTH_ORIGIN, COGNITO_CLIENT_ID,
// STATE_KEY_PARAM); a missing or malformed value throws. There is no fallback to a hard-coded host or client id, so the
// same code serves gamma (https://mcp-gamma.jreese.net) and, later, production (https://mcp.jreese.net).
export const PROFILE = "enceladus";
export const DEFAULT_STATE_KEY_PARAM = "/enceladus/mcp-signin/state-key";
export const EXACT_CALLBACKS = [
  "https://claude.ai/api/mcp/auth_callback",
  "https://claude.com/api/mcp/auth_callback",
  "https://www.cursor.com/agents/mcp/oauth/callback",
  "cursor://anysphere.cursor-mcp/oauth/callback",
];

export function requireOrigin(env, name) {
  const v = String((env ?? {})[name] ?? "").trim().replace(/\/+$/, "");
  if (!/^https:\/\/[^/\s]+$/.test(v)) throw new Error(`${name} is missing or not an https origin`);
  return v;
}

/** The Cognito public client the stack created (a stack output reaches the function as COGNITO_CLIENT_ID). */
export function requireClientId(env) {
  const v = String((env ?? {}).COGNITO_CLIENT_ID ?? "").trim();
  if (!/^[a-z0-9]{20,40}$/.test(v)) throw new Error("COGNITO_CLIENT_ID is missing or not a Cognito app client id");
  return v;
}

/** SSM SecureString holding the HMAC state key (created out of band; the stack never makes or prints it). */
export function stateKeyParam(env = process.env) {
  const v = String((env ?? {}).STATE_KEY_PARAM ?? DEFAULT_STATE_KEY_PARAM).trim();
  if (!/^\/[A-Za-z0-9_.\-/]+$/.test(v)) throw new Error("STATE_KEY_PARAM is not an SSM parameter name");
  return v;
}

/** Connect URL = connector url + mount ("/" mount adds nothing). */
export function connectorUrl(c) {
  const base = String(c.url).replace(/\/+$/, "");
  const mount = !c.mount || c.mount === "/" ? "" : c.mount;
  return base + mount;
}

/**
 * The RFC 8707 resources this service signs in: the enceladus-profile connectors served from THIS service's own origin
 * (sign_in_service: self). Gamma therefore accepts only https://mcp-gamma.jreese.net, production only https://mcp.jreese.net.
 */
export function resourcesFromFleet(fleet, baseUrl) {
  return (fleet?.connectors ?? [])
    .filter((c) => c.profile === PROFILE && c.url && String(c.url).replace(/\/+$/, "") === baseUrl)
    .map(connectorUrl);
}

export function buildConfig({ fleet, stateKey, env = process.env }) {
  if (!stateKey) throw new Error("state key is empty");
  const baseUrl = requireOrigin(env, "CONNECT_ORIGIN");
  const authOrigin = requireOrigin(env, "AUTH_ORIGIN");
  const clientId = requireClientId(env);
  const resources = resourcesFromFleet(fleet, baseUrl);
  if (resources.length === 0) throw new Error(`fleet.json has no ${PROFILE} connector at ${baseUrl}`);
  return {
    baseUrl,
    profile: {
      kind: "cognito",
      authorizeUrl: `${authOrigin}/oauth2/authorize`,
      tokenUrl: `${authOrigin}/oauth2/token`,
      revokeUrl: `${authOrigin}/oauth2/revoke`,
      clientId,
      scopes: ["openid", "email", "profile"],
    },
    supportedClients: { exact: EXACT_CALLBACKS, loopback: true },
    resources,
    stateKey,
  };
}
