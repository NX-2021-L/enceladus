export interface AppSyncEventsConfig {
  httpHost: string
  realtimeHost: string
  apiKey: string
  region: string
  feedChannel: string
  /**
   * DVP-TSK-928: Cognito-authenticated channel namespace (06-appsync-events.yaml `authed`). When set, a signed-in
   * session subscribes to `/<namespace>/<channel>` with its Cognito token instead of the API key; with no session the
   * client falls back to the API-key namespaces -- but only when an API key is configured; with none (production)
   * a signed-out client does not connect at all. Empty/absent keeps the API-key transport only (rollout is opt-in:
   * set the VITE_APPSYNC_AUTHED_NAMESPACE variable for the plane once its CFN stack carries the namespace).
   */
  authedNamespace?: string
  enabled: boolean
}

/** AppSync namespace names are alphanumerics and hyphens only (no slashes, no dots). */
const NAMESPACE_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,48}[A-Za-z0-9])?$/

/** Prefix a channel path ("/feed/updates") with the Cognito namespace ("/authed/feed/updates"). */
export function authedChannel(namespace: string, channel: string): string {
  return `/${namespace}${channel.startsWith('/') ? channel : `/${channel}`}`
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

  const rawNamespace = (import.meta.env.VITE_APPSYNC_AUTHED_NAMESPACE ?? '').trim().replace(/^\/+|\/+$/g, '')
  const authedNamespace = NAMESPACE_PATTERN.test(rawNamespace) ? rawNamespace : ''

  // DVP-TSK-928 (E41-R2): production is Cognito-only and ships NO API key, so a Cognito namespace alone enables
  // realtime. With no apiKey the client never falls back to one (appsyncRealtimeClient: no session => no socket).
  const enabled = Boolean(httpHost && realtimeHost && (apiKey || authedNamespace))

  return { httpHost, realtimeHost, apiKey, region, feedChannel, authedNamespace, enabled }
}
