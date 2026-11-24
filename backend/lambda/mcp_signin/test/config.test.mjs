import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { buildConfig, EXACT_CALLBACKS, stateKeyParam, resourcesFromFleet, DEFAULT_STATE_KEY_PARAM } from "../config.mjs";

const CLIENT = "a1b2c3d4e5f6g7h8i9j0k1l2m3";
const env = {
  CONNECT_ORIGIN: "https://mcp-gamma.jreese.net",
  AUTH_ORIGIN: "https://enceladus-status-356364570033.auth.us-east-1.amazoncognito.com",
  COGNITO_CLIENT_ID: CLIENT,
};
const fleet = JSON.parse(readFileSync(new URL("../fleet.enceladus.json", import.meta.url), "utf8"));
const key = "k".repeat(32);

test("gamma config: Cognito endpoints, the stack's client id, same-origin resource only", () => {
  const cfg = buildConfig({ fleet, stateKey: key, env });
  assert.equal(cfg.baseUrl, "https://mcp-gamma.jreese.net");
  assert.equal(cfg.profile.clientId, CLIENT);
  assert.deepEqual(cfg.profile.scopes, ["openid", "email", "profile"]);
  assert.equal(cfg.profile.authorizeUrl, `${env.AUTH_ORIGIN}/oauth2/authorize`);
  assert.equal(cfg.profile.tokenUrl, `${env.AUTH_ORIGIN}/oauth2/token`);
  assert.equal(cfg.profile.revokeUrl, `${env.AUTH_ORIGIN}/oauth2/revoke`);
  assert.deepEqual(cfg.resources, ["https://mcp-gamma.jreese.net"]);
  assert.deepEqual(cfg.supportedClients, { exact: EXACT_CALLBACKS, loopback: true });
  assert.equal(cfg.stateKey, key);
});

test("production reuse: the same code with the prod origin serves only the prod connector", () => {
  const cfg = buildConfig({ fleet, stateKey: key, env: { ...env, CONNECT_ORIGIN: "https://mcp.jreese.net/" } });
  assert.equal(cfg.baseUrl, "https://mcp.jreese.net");
  assert.deepEqual(cfg.resources, ["https://mcp.jreese.net"]);
});

test("an origin with no matching enceladus connector is refused", () => {
  assert.throws(() => buildConfig({ fleet, stateKey: key, env: { ...env, CONNECT_ORIGIN: "https://other.example.test" } }), /no enceladus connector/);
  assert.throws(() => buildConfig({ fleet: { connectors: [] }, stateKey: key, env }), /no enceladus connector/);
  // a connector of another profile at the same origin does not count
  const other = { connectors: [{ name: "x", url: "https://mcp-gamma.jreese.net", mount: "/", profile: "thepup" }] };
  assert.equal(resourcesFromFleet(other, "https://mcp-gamma.jreese.net").length, 0);
});

test("a connector mount is part of the resource", () => {
  const f = { connectors: [{ name: "x", url: "https://mcp-gamma.jreese.net/", mount: "/mcp", profile: "enceladus" }] };
  assert.deepEqual(resourcesFromFleet(f, "https://mcp-gamma.jreese.net"), ["https://mcp-gamma.jreese.net/mcp"]);
});

test("an empty state key is refused", () => {
  assert.throws(() => buildConfig({ fleet, stateKey: "", env }), /state key/);
});

test("missing or malformed origins and client id throw; there is no fallback", () => {
  assert.throws(() => buildConfig({ fleet, stateKey: key, env: {} }), /CONNECT_ORIGIN/);
  assert.throws(() => buildConfig({ fleet, stateKey: key, env: { ...env, CONNECT_ORIGIN: "mcp-gamma.jreese.net" } }), /CONNECT_ORIGIN/);
  assert.throws(() => buildConfig({ fleet, stateKey: key, env: { ...env, CONNECT_ORIGIN: "http://mcp-gamma.jreese.net" } }), /CONNECT_ORIGIN/);
  assert.throws(() => buildConfig({ fleet, stateKey: key, env: { ...env, AUTH_ORIGIN: "" } }), /AUTH_ORIGIN/);
  assert.throws(() => buildConfig({ fleet, stateKey: key, env: { ...env, COGNITO_CLIENT_ID: "" } }), /COGNITO_CLIENT_ID/);
  assert.throws(() => buildConfig({ fleet, stateKey: key, env: { ...env, COGNITO_CLIENT_ID: "not a client id!" } }), /COGNITO_CLIENT_ID/);
});

test("a trailing slash on an origin is dropped", () => {
  const cfg = buildConfig({ fleet, stateKey: key, env: { ...env, AUTH_ORIGIN: `${env.AUTH_ORIGIN}/` } });
  assert.equal(cfg.profile.tokenUrl, `${env.AUTH_ORIGIN}/oauth2/token`);
});

test("state key parameter defaults to /enceladus/mcp-signin/state-key and rejects a malformed override", () => {
  assert.equal(DEFAULT_STATE_KEY_PARAM, "/enceladus/mcp-signin/state-key");
  assert.equal(stateKeyParam({}), "/enceladus/mcp-signin/state-key");
  assert.equal(stateKeyParam({ STATE_KEY_PARAM: "/enceladus/mcp-signin-prod/state-key" }), "/enceladus/mcp-signin-prod/state-key");
  assert.throws(() => stateKeyParam({ STATE_KEY_PARAM: "no-leading-slash" }), /STATE_KEY_PARAM/);
});

test("the committed registry carries the enceladus profile and both connectors, and no secret-shaped field", () => {
  assert.equal(fleet.profiles.enceladus.sign_in_service, "self");
  assert.deepEqual(fleet.connectors.map((c) => c.name), ["enceladus", "enceladus-gamma"]);
  assert.ok(!/secret|password|token_key/i.test(JSON.stringify(fleet)));
});
