/**
 * ENC-TSK-M37 / ENC-TSK-M57 -- the "Refresh App" control's force-activate path.
 *
 * M37 introduced the "App refresh" menu item (AppShell.tsx, above Log out) so a
 * waiting service worker could be force-activated instead of only ever showing
 * the dismiss-only "App update available" Flashbar. It captured registerSW's
 * return value (vite-plugin-pwa's `updateSW`, semantics: skipWaiting + reload
 * once the new worker takes control) via setUpdateSW().
 *
 * M57 (ENC-ISS-525): that alone was not enough. `updateSW(true)` only activates
 * a worker that is ALREADY waiting -- but an always-loaded SPA may not have
 * re-checked for a new service worker since the tab opened, so after a fresh
 * gamma deploy there is often NO waiting worker yet and `updateSW(true)`
 * silently no-ops (it does not even reload). Clicking "App refresh" then appears
 * dead and the user is forced into a manual hard reload. `refreshApp()` now:
 *   1. forces `registration.update()` so the browser notices a freshly deployed
 *      worker,
 *   2. activates it (skipWaiting) and reloads when one is waiting, and
 *   3. always falls back to a real reload so the freshest shell loads even when
 *      no new worker is found (the app shell is served NetworkFirst, so a reload
 *      pulls the latest index.html + content-hashed bundles from the network).
 */

type UpdateSWFn = (reloadPage?: boolean) => Promise<void>

let updateSWRef: UpdateSWFn | null = null

/** Called once from main.tsx with the function registerSW() returns. */
export function setUpdateSW(fn: UpdateSWFn): void {
  updateSWRef = fn
}

/** skipWaiting the waiting worker and reload once it takes control. Used when
 *  vite-plugin-pwa's `updateSW` was never captured. Reloads on a timeout too,
 *  in case `controllerchange` never fires (some browsers/edge cases). */
function activateWaitingWorker(registration: ServiceWorkerRegistration): Promise<void> {
  return new Promise((resolve) => {
    let settled = false
    const finish = () => {
      if (settled) return
      settled = true
      navigator.serviceWorker.removeEventListener('controllerchange', finish)
      window.location.reload()
      resolve()
    }
    navigator.serviceWorker.addEventListener('controllerchange', finish)
    registration.waiting?.postMessage({ type: 'SKIP_WAITING' })
    setTimeout(finish, 3000)
  })
}

/** Force-loads the newest deployed build. Forces an update check first (an
 *  always-open SPA may not have re-checked since load), activates a waiting
 *  worker when present, and otherwise falls back to a plain reload so the
 *  NetworkFirst app shell still pulls the latest index.html + hashed bundles.
 *  ENC-ISS-525. */
export async function refreshApp(): Promise<void> {
  try {
    if ('serviceWorker' in navigator) {
      const registration = await navigator.serviceWorker.getRegistration()
      if (registration) {
        // Force the browser to look for a newer worker before we conclude there
        // is nothing to activate -- this is the check M37 was missing, and the
        // reason a stale-but-open tab's "App refresh" click did nothing.
        await registration.update()
        if (registration.waiting) {
          if (updateSWRef) {
            // vite-plugin-pwa's updateSW: skipWaiting + reload-on-controllerchange.
            await updateSWRef(true)
            return
          }
          await activateWaitingWorker(registration)
          return
        }
      }
    }
  } catch {
    // Any service-worker error -> fall through to a plain reload below.
  }
  window.location.reload()
}
