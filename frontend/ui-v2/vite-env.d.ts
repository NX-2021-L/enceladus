/// <reference types="vite/client" />
/// <reference types="vite-plugin-pwa/client" />

interface ImportMetaEnv {
  /**
   * Base URL for the Enceladus read API. Mirrors the existing app's
   * `normalizeApiBaseUrl(import.meta.env.VITE_API_BASE_URL)` default of
   * `/api/v1` (see frontend/ui/src/api/projects.ts). The tracker record-fetch
   * path is `${VITE_API_BASE}/tracker/{project}/{type}/{id}` and documents are
   * `${VITE_API_BASE}/documents/{id}`.
   */
  readonly VITE_API_BASE?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}

/**
 * ENC-TSK-M37 — build-injected version string (package.json version + short
 * git SHA), stamped via `define` in vite.config.ts. Rendered in the top-bar
 * version tag on every screen (spec SS4).
 */
declare const __APP_VERSION__: string
