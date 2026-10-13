/**
 * Session teardown for manual logout from the cockpit shell.
 *
 * DVP-TSK-B41: the refresh token lives in an HttpOnly cookie the page cannot
 * touch, so logging out must ask the server to revoke it and clear the cookies
 * (POST /api/v1/auth/logout) and WAIT for that to settle before leaving the
 * page. The previous version fired a never-awaited POST at a route that did not
 * exist (404) and navigated immediately, so the cookie survived and the app
 * signed straight back in on reload.
 */

import { queryClient } from '../api/queryClient'

const SESSION_LS_KEY = 'enceladus:session_last_active'
export const LOGOUT_URL = '/api/v1/auth/logout'
/** Same CSRF header the @io-kit/auth cognitoAdapter sends on its edge calls (refresh, logout). */
const EDGE_CSRF_HEADERS = { 'X-Requested-With': 'io-kit' }
/** Upper bound on the logout request itself: a hung edge must not trap the user on a half-logged-out page. */
const LOGOUT_REQUEST_TIMEOUT_MS = 8000
/** Upper bound on the service-worker / CacheStorage teardown. */
export const CLEANUP_TIMEOUT_MS = 1500

/** Resolve with the promise's value, or undefined when it rejects or `ms` elapses. */
function settleWithin<T>(work: Promise<T>, ms: number): Promise<T | undefined> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(undefined), ms)
    work.then(
      (value) => {
        clearTimeout(timer)
        resolve(value)
      },
      () => {
        clearTimeout(timer)
        resolve(undefined)
      },
    )
  })
}

/** Only an https URL from the logout response is followed; anything else falls back to '/'. */
function safeLogoutUrl(value: unknown): string | null {
  if (typeof value !== 'string' || !value) return null
  try {
    return new URL(value).protocol === 'https:' ? value : null
  } catch {
    return null
  }
}

/** POST the logout and resolve once it has SETTLED (success, HTTP error, network error or timeout). */
async function requestServerLogout(): Promise<string | null> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), LOGOUT_REQUEST_TIMEOUT_MS)
  try {
    const res = await fetch(LOGOUT_URL, {
      method: 'POST',
      credentials: 'include',
      keepalive: true,
      headers: EDGE_CSRF_HEADERS,
      signal: controller.signal,
    })
    if (!res.ok) return null
    const body = (await res.json()) as { logout_url?: unknown } | null
    return safeLogoutUrl(body?.logout_url)
  } catch {
    return null
  } finally {
    clearTimeout(timer)
  }
}

async function clearServiceWorkersAndCaches(): Promise<void> {
  const tasks: Promise<unknown>[] = []
  if ('serviceWorker' in navigator) {
    tasks.push(
      navigator.serviceWorker
        .getRegistrations()
        .then((regs) => Promise.all(regs.map((r) => r.unregister()))),
    )
  }
  if (typeof caches !== 'undefined') {
    tasks.push(caches.keys().then((keys) => Promise.all(keys.map((k) => caches.delete(k)))))
  }
  // allSettled: one failing teardown must not skip the other.
  await Promise.allSettled(tasks)
}

function clearClientState(): void {
  try {
    queryClient.clear()
  } catch {
    /* nothing to clear */
  }
  try {
    localStorage.removeItem(SESSION_LS_KEY)
    sessionStorage.clear()
  } catch {
    /* storage disabled (private mode) */
  }
  try {
    document.cookie = 'enceladus_session_at=; Path=/enceladus; Secure; SameSite=None; Max-Age=0'
  } catch {
    /* cookies disabled */
  }
}

let inFlight: Promise<void> | null = null

/**
 * Log out: (1) await the server logout (revoke + cookie clear), (2) clear client
 * state, (3) leave via the Hosted-UI logout URL when the server returned one,
 * else '/'. Navigation is the last step and always happens, even when every
 * earlier step fails or hangs. Concurrent calls share one run.
 */
export function performLogout(): Promise<void> {
  if (inFlight) return inFlight
  inFlight = (async () => {
    let logoutUrl: string | null = null
    try {
      logoutUrl = await requestServerLogout()
      clearClientState()
      await settleWithin(clearServiceWorkersAndCaches(), CLEANUP_TIMEOUT_MS)
    } finally {
      window.location.replace(logoutUrl || '/')
      inFlight = null
    }
  })()
  return inFlight
}
