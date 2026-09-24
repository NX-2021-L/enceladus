/**
 * Session teardown for manual logout from the cockpit shell.
 * Mirrors frontend/ui/src/lib/logout.ts — clears client state and revokes cookies.
 */

import { queryClient } from '../api/queryClient'

const SESSION_LS_KEY = 'enceladus:session_last_active'
const REVOKE_URL = '/api/v1/auth/revoke'

export function performLogout(): void {
  queryClient.clear()
  localStorage.removeItem(SESSION_LS_KEY)
  document.cookie =
    'enceladus_session_at=; Path=/enceladus; Secure; SameSite=None; Max-Age=0'

  fetch(REVOKE_URL, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
  }).catch(() => {})

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker
      .getRegistrations()
      .then((regs) => Promise.all(regs.map((r) => r.unregister())))
      .catch(() => {})
  }

  if ('caches' in window) {
    caches
      .keys()
      .then((keys) => Promise.all(keys.map((k) => caches.delete(k))))
      .catch(() => {})
  }

  window.location.assign('/')
}
