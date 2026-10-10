// DVP-TSK-861: @io-kit/auth client in cookie mode against backend/lambda/auth_refresh
// (the auth edge). The refresh token stays in the HttpOnly enceladus_refresh_token
// cookie; the page only holds the short-lived id token in memory. Login still uses
// the Hosted-UI authorize redirect (authConfig.redirectToLogin) and the server-side
// code exchange at GET /api/v1/auth/callback.
import { cognitoAdapter, createAuthClient } from '@io-kit/auth'
import { redirectToLogin } from './authConfig'

export const AUTH_EDGE_BASE = '/api/v1/auth'

export const auth = createAuthClient({
  stack: 'enceladus',
  adapter: cognitoAdapter({
    userPoolId: 'us-east-1_b2D0V3E1k',
    clientId: '6q607dk3liirhtecgps7hifmlk',
    edgeBase: AUTH_EDGE_BASE,
    bearer: 'id',
  }),
  authEdgeBase: AUTH_EDGE_BASE,
  apiBase: '/api/v1',
  permissions: { manifestUrl: '/auth/manifest' },
  // A refresh that cannot recover the session sends the user back to sign-in
  // instead of dead-ending on a failed request (ENC-ISS-546).
  onReauthRequired: () => redirectToLogin(),
})
