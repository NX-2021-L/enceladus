/**
 * DVP-TSK-B42 -- "App refresh" is a deterministic, brute-force reset.
 *
 * The previous path (ENC-TSK-M37 / M57, ENC-ISS-525) tried to be clever: force a
 * service-worker update check, skipWaiting a waiting worker, wait for
 * controllerchange, fall back to a plain reload. It was flaky -- a stale shell,
 * a hung update() or a never-firing controllerchange left the app wrong or
 * looking dead. io's spec replaces it: one press, everything stops, the server
 * signals a fresh app, the client deletes everything it holds and hard-reloads.
 *
 *   1. a full-screen blocking "Refreshing…" overlay, immediately
 *   2. GET /api/v1/app/refresh (Clear-Site-Data: cache, storage, executionContexts; NOT cookies)
 *   3. unregister every service worker registration
 *   4. delete every CacheStorage cache
 *   5. localStorage.clear() + sessionStorage.clear()
 *   6. delete every IndexedDB database
 *   7. location.replace('/?_r=' + Date.now())
 *
 * Every step has a timeout and a try/catch, so ANY failure or hang still ends in
 * step 7. Normal-operation service-worker auto-update (registerSW in main.tsx,
 * watchForUpdates) is untouched; only this manual path is replaced.
 */

import { signalAppRefresh } from '../api/appRefresh'

/** Cap on the server round trip. */
export const REFRESH_FETCH_TIMEOUT_MS = 4000
/** Cap on each client-side deletion step. */
export const REFRESH_STEP_TIMEOUT_MS = 2000
const OVERLAY_ID = 'ev2-refresh-overlay'

/** Run one reset step: never throws, never outlives `ms`. */
async function runStep(work: () => unknown, ms: number): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    await Promise.race([
      Promise.resolve().then(work),
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, ms)
      }),
    ])
  } catch {
    // Any failure falls through to the next step -- the reload must always happen.
  } finally {
    if (timer !== undefined) clearTimeout(timer)
  }
}

/** Blocking overlay, appended synchronously to <body> (outside React) and the app made inert behind it. */
function showRefreshOverlay(): void {
  try {
    if (document.getElementById(OVERLAY_ID)) return
    const overlay = document.createElement('div')
    overlay.id = OVERLAY_ID
    overlay.className = 'ev2-refresh-overlay'
    overlay.setAttribute('role', 'alertdialog')
    overlay.setAttribute('aria-modal', 'true')
    overlay.setAttribute('aria-busy', 'true')
    overlay.setAttribute('aria-label', 'Refreshing')
    const text = document.createElement('p')
    text.className = 'ev2-refresh-overlay__text'
    text.textContent = 'Refreshing…'
    overlay.appendChild(text)
    document.body.appendChild(overlay)
    // Keyboard and assistive tech stop too: nothing behind the overlay is reachable.
    document.getElementById('root')?.setAttribute('inert', '')
  } catch {
    // A missing DOM must not stop the reset.
  }
}

async function unregisterServiceWorkers(): Promise<void> {
  if (!('serviceWorker' in navigator)) return
  const registrations = await navigator.serviceWorker.getRegistrations()
  await Promise.allSettled(registrations.map((registration) => registration.unregister()))
}

async function deleteAllCaches(): Promise<void> {
  if (typeof caches === 'undefined') return
  const keys = await caches.keys()
  await Promise.allSettled(keys.map((key) => caches.delete(key)))
}

function clearWebStorage(): void {
  // Separate try blocks: a throwing localStorage must not skip sessionStorage.
  try {
    localStorage.clear()
  } catch {
    /* storage disabled */
  }
  try {
    sessionStorage.clear()
  } catch {
    /* storage disabled */
  }
}

async function deleteAllIndexedDb(): Promise<void> {
  if (typeof indexedDB === 'undefined' || typeof indexedDB.databases !== 'function') return
  const databases = await indexedDB.databases()
  await Promise.allSettled(
    databases.map(
      (db) =>
        new Promise<void>((resolve) => {
          if (!db.name) return resolve()
          const request = indexedDB.deleteDatabase(db.name)
          // `blocked` = another connection is still open; the delete completes once the reload closes it.
          request.onsuccess = request.onerror = request.onblocked = () => resolve()
        }),
    ),
  )
}

let running: Promise<void> | null = null

/** One press resets the app. Resolves only if the browser did not navigate away; a repeat press shares the run. */
export function refreshApp(): Promise<void> {
  if (running) return running
  showRefreshOverlay()
  running = (async () => {
    try {
      await runStep(signalAppRefresh, REFRESH_FETCH_TIMEOUT_MS)
      await runStep(unregisterServiceWorkers, REFRESH_STEP_TIMEOUT_MS)
      await runStep(deleteAllCaches, REFRESH_STEP_TIMEOUT_MS)
      await runStep(clearWebStorage, REFRESH_STEP_TIMEOUT_MS)
      await runStep(deleteAllIndexedDb, REFRESH_STEP_TIMEOUT_MS)
    } finally {
      window.location.replace('/?_r=' + Date.now())
      running = null
    }
  })()
  return running
}
