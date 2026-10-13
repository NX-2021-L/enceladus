// DVP-TSK-861: @io-kit/auth client in cookie mode against backend/lambda/auth_refresh
// (the auth edge). The refresh token stays in the HttpOnly enceladus_refresh_token
// cookie; the page only holds the short-lived id token in memory. Login still uses
// the Hosted-UI authorize redirect (authConfig.redirectToLogin) and the server-side
// code exchange at GET /api/v1/auth/callback.
import { cognitoAdapter, createAuthClient } from '@io-kit/auth'
import { redirectToLogin } from './authConfig'

export const AUTH_EDGE_BASE = '/api/v1/auth'

const cognito = cognitoAdapter({
  userPoolId: 'us-east-1_b2D0V3E1k',
  clientId: '6q607dk3liirhtecgps7hifmlk',
  edgeBase: AUTH_EDGE_BASE,
  bearer: 'id',
})

// DVP-TSK-928: the auth client keeps its bearer private (it only exposes authFetch), but AppSync Events needs the
// raw Cognito token in the WebSocket auth header. Every refresh runs through this adapter, so record the latest
// id token here, in memory only, with the same lifetime contract as the client's own token.
interface CapturedToken {
  token: string
  exp: number
}
let capturedToken: CapturedToken | null = null

/** JWT `exp` (epoch seconds) from the unverified payload; AppSync verifies the signature, we only need the clock. */
function jwtExp(token: string): number | undefined {
  try {
    const payload = token.split('.')[1]
    if (!payload) return undefined
    const json = atob(payload.replace(/-/g, '+').replace(/_/g, '/'))
    const exp = (JSON.parse(json) as { exp?: unknown }).exp
    return typeof exp === 'number' ? exp : undefined
  } catch {
    return undefined
  }
}

const baseRefresh = cognito.refresh.bind(cognito)
cognito.refresh = async () => {
  const result = await baseRefresh()
  const token = result.idToken ?? result.accessToken
  capturedToken = { token, exp: jwtExp(token) ?? result.exp }
  return result
}

export const auth = createAuthClient({
  stack: 'enceladus',
  adapter: cognito,
  authEdgeBase: AUTH_EDGE_BASE,
  apiBase: '/api/v1',
  permissions: { manifestUrl: '/auth/manifest' },
  // A refresh that cannot recover the session sends the user back to sign-in
  // instead of dead-ending on a failed request (ENC-ISS-546).
  onReauthRequired: () => redirectToLogin(),
})

/** Seconds of remaining life below which a captured token is treated as stale. */
const REALTIME_TOKEN_SKEW_SECONDS = 60

function liveToken(): string | null {
  if (!capturedToken) return null
  return capturedToken.exp - Date.now() / 1000 > REALTIME_TOKEN_SKEW_SECONDS ? capturedToken.token : null
}

/**
 * DVP-TSK-928: the signed-in user's Cognito ID token for AppSync Events (the `AMAZON_COGNITO_USER_POOLS` authorizer
 * accepts it as the `Authorization` header). Resolves null when there is no session, so the realtime client can
 * fall back to the API-key namespaces; rejects only when a session exists but a token cannot be produced.
 */
export async function getRealtimeAuthToken(): Promise<string | null> {
  const session = await auth.ready()
  if (session.status !== 'authenticated') {
    capturedToken = null
    return null
  }
  const cached = liveToken()
  if (cached) return cached
  // Locked, cross-tab-deduplicated refresh first. When a peer tab refreshed, the client adopts the peer's token
  // without running this adapter, so the capture can still be stale: refresh through the adapter directly.
  await auth.refresh()
  const refreshed = liveToken()
  if (refreshed) return refreshed
  await cognito.refresh()
  return liveToken()
}
