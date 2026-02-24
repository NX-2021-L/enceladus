/**
 * auth.ts — Client for the Enceladus auth API.
 *
 * POST /api/v1/auth/refresh
 *   Sends the enceladus_refresh_token cookie (HttpOnly, credentials:'include').
 *   On success, the server sets a new enceladus_id_token cookie and
 *   enceladus_session_at cookie in the response.
 */

const REFRESH_URL = '/api/v1/auth/refresh'

/**
 * Attempt to refresh the Cognito id_token using the stored refresh token.
 * Returns true if the server returned fresh credentials, false otherwise.
 *
 * This function never throws — all errors are caught and return false.
 */
export async function refreshCredentials(): Promise<boolean> {
  try {
    const res = await fetch(REFRESH_URL, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
    })
    if (!res.ok) return false
    const data = await res.json()
    return data.success === true
  } catch {
    return false
  }
}
