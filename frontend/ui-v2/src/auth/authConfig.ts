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
 */

const COGNITO_HOSTED_UI_DOMAIN =
  'https://enceladus-status-356364570033.auth.us-east-1.amazoncognito.com'
const COGNITO_CLIENT_ID = '6q607dk3liirhtecgps7hifmlk'
const COGNITO_SCOPES = 'openid email profile'
const OAUTH_REDIRECT_URI =
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
