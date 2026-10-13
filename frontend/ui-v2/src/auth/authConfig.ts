/**
 * ENC-TSK-K95 — Cognito Hosted-UI OAuth2 (authorization-code) login config for
 * the v4 cockpit.
 *
 * Public app client (no secret): the SPA only starts the flow. The one-time
 * code is exchanged server-side at `GET /api/v1/auth/callback` (auth_refresh),
 * which sets the session cookies and 302s back to the pre-login path. So there
 * is no token/secret handling in the browser and no SPA callback route.
 *
 * These are public identifiers (client id + hosted-UI domain ship in every
 * OAuth redirect regardless). REDIRECT_URI is a FIXED registered Cognito
 * callback — it must match byte-for-byte both the redirect_uri auth_refresh
 * uses for the token exchange and a CallbackURL on the app client.
 *
 * DVP-TSK-B24: the hosted-UI domain is the managed-login v2 custom domain
 * (auth.enceladus.jreese.net), which is what carries Cognito-native passkeys
 * (WebAuthn, RP = that domain) for this client. The classic prefix domain
 * (enceladus-status-356364570033.auth.us-east-1.amazoncognito.com) is kept
 * untouched for the MCP / Claude-connector DCR clients; the PWA no longer uses
 * it. VITE_COGNITO_HOSTED_UI_DOMAIN overrides the domain at build time.
 */

const COGNITO_HOSTED_UI_DOMAIN =
  import.meta.env.VITE_COGNITO_HOSTED_UI_DOMAIN || 'https://auth.enceladus.jreese.net'
const COGNITO_CLIENT_ID = '6q607dk3liirhtecgps7hifmlk'
const COGNITO_SCOPES = 'openid email profile'
// ENC-TSK-P51: per-plane redirect. The deploy lane bakes VITE_OAUTH_REDIRECT_URI
// at build (prod -> https://enceladus.jreese.net/api/v1/auth/callback); the gamma
// URI stays as the default so local/dev and gamma builds are unchanged. The value
// must byte-match auth_refresh's WEBUI_OAUTH_REDIRECT_URI and a registered
// Cognito callback (redirect_mismatch class: ENC-ISS-124/125).
const OAUTH_REDIRECT_URI =
  import.meta.env.VITE_OAUTH_REDIRECT_URI ||
  'https://enceladus-gamma.jreese.net/api/v1/auth/callback'

/** base64url so it round-trips through the Python `base64.urlsafe_b64decode`
 *  in auth_refresh (standard btoa yields '+', '/', '=' which corrupt it). */
function base64UrlEncode(input: string): string {
  return btoa(input)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

/** Build the Cognito `/oauth2/authorize` URL, carrying the current in-app path
 *  in `state` so the callback can return the user to where they were. */
export function buildLoginUrl(): string {
  const currentPath = window.location.pathname + window.location.search
  const state = base64UrlEncode(currentPath)
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: COGNITO_CLIENT_ID,
    redirect_uri: OAUTH_REDIRECT_URI,
    scope: COGNITO_SCOPES,
    state,
  })
  return `${COGNITO_HOSTED_UI_DOMAIN}/oauth2/authorize?${params.toString()}`
}

/** Start the login flow (full-page navigation to the Cognito Hosted UI). */
export function redirectToLogin(): void {
  window.location.assign(buildLoginUrl())
}

/** DVP-TSK-B24: managed-login v2 "add a passkey" URL. Uses the SAME registered
 *  redirect_uri as login, so Cognito returns to /api/v1/auth/callback with
 *  `?result=<success|invalid_session|...>` (no `code`), which auth_refresh
 *  turns into `/?passkey_result=...` for the SPA notice. */
export function buildAddPasskeyUrl(): string {
  const params = new URLSearchParams({
    client_id: COGNITO_CLIENT_ID,
    redirect_uri: OAUTH_REDIRECT_URI,
  })
  return `${COGNITO_HOSTED_UI_DOMAIN}/passkeys/add?${params.toString()}`
}

/** Start the add-a-passkey flow (full-page navigation to managed login). */
export function redirectToAddPasskey(): void {
  window.location.assign(buildAddPasskeyUrl())
}
