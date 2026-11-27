// Behaviour of the kit's createSignInService as configured here. Needs @io-kit/mcp 0.3.2 installed (CodeArtifact);
// without it these tests are SKIPPED, loudly, and config.test.mjs still runs offline.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { buildConfig } from "../config.mjs";

let createSignInService;
try {
  ({ createSignInService } = await import("@io-kit/mcp/as"));
} catch {
  console.warn("SKIP service tests: @io-kit/mcp is not installed (export CODEARTIFACT_AUTH_TOKEN and run npm install)");
}
const skip = createSignInService ? false : "@io-kit/mcp not installed";

const CLIENT = "a1b2c3d4e5f6g7h8i9j0k1l2m3";
const BASE = "https://mcp-gamma.jreese.net";
const COGNITO = "https://enceladus-status-356364570033.auth.us-east-1.amazoncognito.com";
const env = { CONNECT_ORIGIN: BASE, AUTH_ORIGIN: COGNITO, COGNITO_CLIENT_ID: CLIENT };
const fleet = JSON.parse(readFileSync(new URL("../fleet.enceladus.json", import.meta.url), "utf8"));
const svc = () => createSignInService(buildConfig({ fleet, stateKey: "k".repeat(32), env }));
const post = (path, body) =>
  new Request(`${BASE}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
const authorize = (over = {}) => {
  const q = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT,
    redirect_uri: "https://claude.ai/api/mcp/auth_callback",
    code_challenge: "n3uL0ZrTE-UZW5oxVRy_ZubYC6SNiWKNqLGDEJcm7q8",
    code_challenge_method: "S256",
    state: "st",
    ...over,
  });
  for (const [k, v] of Object.entries(over)) if (v === null) q.delete(k);
  return new Request(`${BASE}/authorize?${q}`);
};

test("authorization-server metadata is same-origin and public-client only", { skip }, async () => {
  const res = await svc().handle(new Request(`${BASE}/.well-known/oauth-authorization-server`));
  assert.equal(res.status, 200);
  const m = await res.json();
  assert.equal(m.issuer, BASE);
  assert.equal(m.authorization_endpoint, `${BASE}/authorize`);
  assert.equal(m.token_endpoint, `${BASE}/token`);
  assert.equal(m.registration_endpoint, `${BASE}/register`);
  assert.equal(m.revocation_endpoint, `${COGNITO}/oauth2/revoke`);
  assert.deepEqual(m.code_challenge_methods_supported, ["S256"]);
  assert.deepEqual(m.token_endpoint_auth_methods_supported, ["none"]);
  assert.deepEqual(m.grant_types_supported, ["authorization_code", "refresh_token"]);
  assert.deepEqual(m.scopes_supported, ["openid", "email", "profile"]);
});

test("/authorize refuses an unknown redirect_uri and never redirects to it", { skip }, async () => {
  for (const uri of ["https://evil.example/cb", "http://example.com/callback", "https://claude.ai/other", ""]) {
    const res = await svc().handle(authorize({ redirect_uri: uri }));
    assert.equal(res.status, 400, uri);
    assert.equal(res.headers.get("location"), null, uri);
    assert.equal((await res.json()).error, "invalid_request");
  }
  assert.equal((await svc().handle(authorize({ redirect_uri: null }))).status, 400);
});

test("/authorize with an allowed redirect goes to Cognito with the stack's client and this service's callback", { skip }, async () => {
  const res = await svc().handle(authorize({ resource: BASE }));
  assert.equal(res.status, 302);
  const to = new URL(res.headers.get("location"));
  assert.equal(`${to.origin}${to.pathname}`, `${COGNITO}/oauth2/authorize`);
  assert.equal(to.searchParams.get("client_id"), CLIENT);
  assert.equal(to.searchParams.get("redirect_uri"), `${BASE}/callback`);
  assert.equal(to.searchParams.get("code_challenge_method"), "S256");
  assert.ok(to.searchParams.get("state").includes("."), "state is the signed blob");
});

test("/authorize accepts the resource as clients send it: Cursor's trailing slash and the MCP path (DVP-TSK-M49)", { skip }, async () => {
  for (const resource of [`${BASE}/`, `${BASE}/mcp`, `${BASE}/mcp/`]) {
    assert.equal((await svc().handle(authorize({ resource }))).status, 302, resource);
  }
});

test("/authorize refuses a wrong client, a missing PKCE challenge and a resource of another host", { skip }, async () => {
  assert.equal((await (await svc().handle(authorize({ client_id: "other" }))).json()).error, "invalid_client");
  assert.equal((await svc().handle(authorize({ code_challenge: null }))).status, 400);
  assert.equal((await (await svc().handle(authorize({ resource: "https://mcp.jreese.net" }))).json()).error, "invalid_target");
});

test("/register refuses a non-allow-listed callback", { skip }, async () => {
  for (const uri of ["https://evil.example/cb", "http://example.com/cb", "https://claude.ai/not-the-callback", "http://localhost:3000/cb#frag", "https://chatgpt.com/other", "https://chatgpt.com.evil.example/connector_platform_oauth_redirect"]) {
    const res = await svc().handle(post("/register", { redirect_uris: [uri] }));
    assert.equal(res.status, 400, uri);
    assert.equal((await res.json()).error, "invalid_redirect_uri");
  }
  assert.equal((await svc().handle(post("/register", { redirect_uris: [] }))).status, 400);
  // one bad URI among good ones refuses the whole registration
  assert.equal((await svc().handle(post("/register", { redirect_uris: ["https://claude.ai/api/mcp/auth_callback", "https://evil.example/cb"] }))).status, 400);
});

test("/register accepts claude.ai, claude.com, Cursor, ChatGPT and loopback and returns the stack's public client", { skip }, async () => {
  for (const uri of [
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
    "https://www.cursor.com/agents/mcp/oauth/callback",
    "cursor://anysphere.cursor-mcp/oauth/callback",
    "https://chatgpt.com/connector_platform_oauth_redirect",
    "http://localhost:8787/callback",
    "http://127.0.0.1:54321/cb",
    "http://[::1]:9000/cb",
  ]) {
    const res = await svc().handle(post("/register", { redirect_uris: [uri] }));
    assert.equal(res.status, 201, uri);
    const body = await res.json();
    assert.equal(body.client_id, CLIENT);
    assert.equal(body.token_endpoint_auth_method, "none");
    assert.equal(body.client_secret, undefined);
  }
});

test("/callback with a tampered state is refused", { skip }, async () => {
  const res = await svc().handle(new Request(`${BASE}/callback?code=c&state=bogus.sig`));
  assert.equal(res.status, 400);
  assert.equal(res.headers.get("location"), null);
});
