/**
 * DVP-TSK-B42 -- the server half of "App refresh": GET /api/v1/app/refresh answers
 * 200 with `Clear-Site-Data: "cache", "storage", "executionContexts"` (not
 * "cookies": the session survives). Lives in src/api because it is a raw fetch
 * (AC-13); the reset sequence itself is src/offline/swUpdate.ts.
 */
export const APP_REFRESH_URL = '/api/v1/app/refresh'

export function signalAppRefresh(): Promise<Response> {
  return fetch(APP_REFRESH_URL, { cache: 'no-store', credentials: 'include' })
}
