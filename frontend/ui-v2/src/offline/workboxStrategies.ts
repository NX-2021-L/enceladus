/**
 * B67 AC-17 — canonical Workbox strategy map (DOC-E470AC8CE9A8 §7.1).
 * vite.config.ts runtimeCaching must stay aligned with these six entries.
 */
export const WORKBOX_STRATEGY_MAP = [
  { id: 'static-assets', handler: 'CacheFirst', routes: 'Vite content-hashed JS/CSS (precache + media)' },
  { id: 's3-payloads', handler: 'CacheFirst', routes: '/mobile/v1/reference/*' },
  { id: 'feed-api', handler: 'StaleWhileRevalidate', routes: '/api/v1/feed*, /feed/corpus*, /mobile/v1/*.json' },
  {
    id: 'record-detail',
    handler: 'NetworkFirst',
    routes: 'GET /api/v1/tracker/*/{type}/{id}, GET /api/v1/documents/*',
    timeoutSeconds: 5,
  },
  { id: 'auth', handler: 'NetworkOnly', routes: '/api/v1/auth*, /callback, /mobile/v1/auth*' },
  {
    // ENC-TSK-N04 (B67 AC-18): queue+replay for this route class is the
    // app-layer mutationQueue (If-Match aware, UI pendingCount), NOT Workbox
    // BackgroundSync — a SW-level queue on the same routes would double-replay.
    id: 'mutations',
    handler: 'NetworkOnly+AppLayerQueue',
    routes: 'PATCH|POST|DELETE /api/v1/tracker/*, /api/v1/documents/*',
  },
] as const

export const APP_SHELL_NETWORK_TIMEOUT_SECONDS = 3

export type WorkboxStrategyId = (typeof WORKBOX_STRATEGY_MAP)[number]['id']
