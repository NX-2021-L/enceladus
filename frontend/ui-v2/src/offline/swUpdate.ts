/**
 * "App refresh" (DVP-TSK-B42): a deterministic, brute-force reset of the installed app. The reset now
 * lives in @io-kit/shell as refreshApp() (ENC-TSK-Q99/R01) so every kit PWA shares one implementation:
 * blocking overlay, GET /api/v1/app/refresh (Clear-Site-Data; cookies untouched), unregister service
 * workers, delete caches, clear web storage and IndexedDB, then location.replace('/?_r=<now>'). Every
 * step is time-boxed, so any failure or hang still ends in the reload. Normal-operation service-worker
 * auto-update (registerSW in main.tsx, watchForUpdates) is untouched.
 */

import { refreshApp as kitRefreshApp } from '@io-kit/shell'
import { APP_REFRESH_URL } from '../api/appRefresh'

/** One press resets the app. Resolves only if the browser did not navigate away; a repeat press shares the run. */
export function refreshApp(): Promise<void> {
  return kitRefreshApp({ signalUrl: APP_REFRESH_URL })
}
