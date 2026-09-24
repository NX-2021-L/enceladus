/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE?: string
  readonly VITE_FEED_BASE_URL?: string
  readonly VITE_APPSYNC_HTTP_HOST?: string
  readonly VITE_APPSYNC_REALTIME_HOST?: string
  readonly VITE_APPSYNC_API_KEY?: string
  readonly VITE_APPSYNC_REGION?: string
  readonly VITE_APPSYNC_FEED_CHANNEL?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
