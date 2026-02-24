/**
 * logout.ts — Centralized cleanup on session end.
 *
 * Called by setLoggedOut() in authState.tsx so every logout path (timer expiry,
 * refresh-token failure, manual logout) gets consistent cleanup:
 *   1. Clear TanStack Query cache (project data in memory)
 *   2. Clear localStorage session timestamp
 *   3. Clear enceladus_session_at cookie (JS-readable)
 *   4. Revoke server-side refresh token (fire-and-forget)
 *   5. Unregister service workers
 *   6. Clear Cache Storage (workbox precache entries)
 */

import { queryClient } from './queryClient'

const SESSION_LS_KEY = 'enceladus:session_last_active'
const REVOKE_URL = '/api/v1/auth/revoke'

export function performLogout(): void {
  // 1. Clear TanStack Query cache
  queryClient.clear()

  // 2. Clear localStorage session timestamp
  localStorage.removeItem(SESSION_LS_KEY)

  // 3. Clear enceladus_session_at cookie
  document.cookie =
    'enceladus_session_at=; Path=/enceladus; Secure; SameSite=None; Max-Age=0'

  // 4. Revoke server-side refresh token (clears HttpOnly cookies too)
  fetch(REVOKE_URL, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
  }).catch(() => {})

  // 5. Unregister service workers
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker
      .getRegistrations()
      .then((regs) => Promise.all(regs.map((r) => r.unregister())))
      .catch(() => {})
  }

  // 6. Clear Cache Storage
  if ('caches' in window) {
    caches
      .keys()
      .then((keys) => Promise.all(keys.map((k) => caches.delete(k))))
      .catch(() => {})
  }
}
