/**
 * ENC-TSK-M37 -- the "Refresh App" control's force-activate path.
 *
 * Before this task the only signal for a waiting service worker was the
 * dismiss-only "App update available" Flashbar (components/OfflineLayer.tsx,
 * driven by offlineStore.swUpdateReady): dismissing it just hid the banner
 * and left the waiting worker waiting forever, so probes kept running
 * against a stale precached shell indefinitely. `registerSW`'s return value
 * (vite-plugin-pwa's `updateSW`, semantics: skipWaiting + reload once the
 * new worker takes control) was never even captured in main.tsx.
 *
 * This module holds that function so any UI surface -- today, the "App
 * refresh" menu item above Log out -- can force the swap.
 */

type UpdateSWFn = (reloadPage?: boolean) => Promise<void>

let updateSWRef: UpdateSWFn | null = null

/** Called once from main.tsx with the function registerSW() returns. */
export function setUpdateSW(fn: UpdateSWFn): void {
  updateSWRef = fn
}

/** Force-activates the waiting service worker (skipWaiting) and reloads once
 *  it takes control. Falls back to a plain reload if no SW registration
 *  exists yet (unsupported browser, or called before registerSW resolves). */
export async function refreshApp(): Promise<void> {
  if (updateSWRef) {
    await updateSWRef(true)
    return
  }
  window.location.reload()
}
