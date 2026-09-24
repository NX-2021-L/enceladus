export interface AppSyncEventsConfig {
  httpHost: string
  realtimeHost: string
  apiKey: string
  region: string
  feedChannel: string
  enabled: boolean
}

function stripProtocol(host: string): string {
  return host.replace(/^https?:\/\//, '').replace(/\/.*$/, '')
}

/** Build config from Vite env. When incomplete, realtime is disabled (S3-only degrade). */
export function getAppSyncEventsConfig(): AppSyncEventsConfig {
  const httpHost = stripProtocol(import.meta.env.VITE_APPSYNC_HTTP_HOST ?? '')
  const realtimeHost = stripProtocol(import.meta.env.VITE_APPSYNC_REALTIME_HOST ?? '')
  const apiKey = (import.meta.env.VITE_APPSYNC_API_KEY ?? '').trim()
  const region = (import.meta.env.VITE_APPSYNC_REGION ?? 'us-west-2').trim()
  const feedChannel = (import.meta.env.VITE_APPSYNC_FEED_CHANNEL ?? '/feed/updates').trim()

  const enabled = Boolean(httpHost && realtimeHost && apiKey)

  return { httpHost, realtimeHost, apiKey, region, feedChannel, enabled }
}
