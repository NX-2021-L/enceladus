/**
 * appsyncRecordChannel.ts — subscribe to a single document's AppSync Events
 * `/records/{document_id}` channel (ENC-TSK-K29 full-record-body contract).
 *
 * frontend/ui has no build-time dependency on frontend/ui-v2 (separate npm
 * packages, no shared workspace), so the multiplexed feed client at
 * frontend/ui-v2/src/realtime/appsyncRealtimeClient.ts (its `watchRecord`
 * method specifically) cannot be imported directly. This is a focused,
 * single-purpose port of that SAME wire protocol — connection_init /
 * connection_ack / subscribe / data frame handling, the `header-<base64url>`
 * auth subprotocol — scoped to exactly what one document detail page needs
 * (one record's channel, on its own socket). The primary `/feed/updates`
 * subscription, cursor/gap bookkeeping, and multi-subscription multiplexing
 * in the ui-v2 client are out of scope here; frontend/ui's live-record
 * updates are DocumentDetailPage-only.
 *
 * frontend/ui has no VITE_APPSYNC_* env wiring yet (ui-v2 is the only
 * package that does). Reads the same variable names ui-v2 uses so a future
 * shared deploy-time config lines up; when they're unset, `enabled` is false
 * and this becomes a no-op (the page still works — outline/body come from
 * the manifest+document fetch either way, just without live push updates).
 */

export interface RecordChannelEvent {
  eventId?: string
  recordId?: string
  record_type?: string
  action?: string
  cursor?: number
  /** Full current record body, per the K29 per-record-channel contract. */
  record?: Record<string, unknown>
}

export type RecordChannelStatus = 'connecting' | 'connected' | 'disconnected'

export interface SubscribeRecordChannelOptions {
  documentId: string
  onEvent: (event: RecordChannelEvent) => void
  onStatusChange?: (status: RecordChannelStatus) => void
  /** Injectable for tests; defaults to the real WebSocket constructor. */
  webSocketFactory?: (url: string, protocols: string[]) => WebSocket
}

interface AppSyncEventsEnv {
  httpHost: string
  realtimeHost: string
  apiKey: string
  enabled: boolean
}

function stripProtocol(host: string): string {
  return host.replace(/^https?:\/\//, '').replace(/\/.*$/, '')
}

function readEnv(): AppSyncEventsEnv {
  const httpHost = stripProtocol(import.meta.env.VITE_APPSYNC_HTTP_HOST ?? '')
  const realtimeHost = stripProtocol(import.meta.env.VITE_APPSYNC_REALTIME_HOST ?? '')
  const apiKey = (import.meta.env.VITE_APPSYNC_API_KEY ?? '').trim()
  return { httpHost, realtimeHost, apiKey, enabled: Boolean(httpHost && realtimeHost && apiKey) }
}

function base64UrlEncode(value: string): string {
  const bytes = new TextEncoder().encode(value)
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function buildAuthSubprotocol(env: AppSyncEventsEnv): string {
  const header = { host: env.httpHost, 'x-api-key': env.apiKey }
  return `header-${base64UrlEncode(JSON.stringify(header))}`
}

const MAX_RECONNECT_ATTEMPTS = 8
const BACKOFF_BASE_MS = 500
const BACKOFF_CAP_MS = 20_000

/**
 * Subscribe to `documentId`'s `/records/{documentId}` channel. Returns an
 * unsubscribe function that closes the socket and cancels any pending
 * reconnect. Safe to call with AppSync env vars unset (frontend/ui's current
 * state) — becomes a no-op that immediately reports 'disconnected'.
 */
export function subscribeToRecordChannel(options: SubscribeRecordChannelOptions): () => void {
  const env = readEnv()
  const setStatus = (status: RecordChannelStatus) => options.onStatusChange?.(status)

  if (!env.enabled) {
    setStatus('disconnected')
    return () => {}
  }

  const wsFactory =
    options.webSocketFactory ?? ((url, protocols) => new WebSocket(url, protocols))
  const channel = `/records/${options.documentId}`

  let socket: WebSocket | null = null
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null
  let reconnectAttempt = 0
  let disposed = false

  function clearReconnect(): void {
    if (reconnectTimer) {
      clearTimeout(reconnectTimer)
      reconnectTimer = null
    }
  }

  function scheduleReconnect(): void {
    if (disposed) return
    reconnectAttempt += 1
    if (reconnectAttempt > MAX_RECONNECT_ATTEMPTS) {
      setStatus('disconnected')
      return
    }
    const exp = Math.min(BACKOFF_CAP_MS, BACKOFF_BASE_MS * 2 ** (reconnectAttempt - 1))
    const delayMs = Math.round(exp * (0.5 + Math.random() * 0.5))
    reconnectTimer = setTimeout(connect, delayMs)
  }

  function connect(): void {
    if (disposed) return
    setStatus('connecting')
    const url = `wss://${env.realtimeHost}/event/realtime`

    let s: WebSocket
    try {
      s = wsFactory(url, ['aws-appsync-event-ws', buildAuthSubprotocol(env)])
    } catch {
      scheduleReconnect()
      return
    }
    socket = s

    s.onopen = () => {
      if (socket !== s) return
      s.send(JSON.stringify({ type: 'connection_init' }))
    }

    s.onmessage = (message: MessageEvent) => {
      if (socket !== s || typeof message.data !== 'string') return

      let frame: { type?: string; id?: string; event?: unknown }
      try {
        frame = JSON.parse(message.data)
      } catch {
        return
      }

      if (frame.type === 'connection_ack') {
        reconnectAttempt = 0
        s.send(
          JSON.stringify({
            type: 'subscribe',
            id: crypto.randomUUID(),
            channel,
            authorization: { host: env.httpHost, 'x-api-key': env.apiKey },
          }),
        )
        setStatus('connected')
        return
      }

      if (frame.type === 'ka' || frame.type === 'error') return

      if (frame.type === 'data' && frame.event != null) {
        try {
          const payload = typeof frame.event === 'string' ? JSON.parse(frame.event) : frame.event
          options.onEvent(payload as RecordChannelEvent)
        } catch {
          // malformed event — drop silently, same posture as the ui-v2 client
        }
      }
    }

    s.onerror = () => {
      // onclose handles reconnect scheduling.
    }

    s.onclose = () => {
      if (socket !== s) return
      socket = null
      if (!disposed) {
        setStatus('disconnected')
        scheduleReconnect()
      }
    }
  }

  connect()

  return () => {
    disposed = true
    clearReconnect()
    if (socket) {
      const s = socket
      socket = null
      s.close()
    }
  }
}
