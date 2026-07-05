import type { AppSyncEventsConfig } from '../api/appsyncConfig'
import type { FeedRealtimeEvent, GapTooLargeSignal } from '../types/feedEvents'

export const GAP_CURSOR_THRESHOLD = 1_000_000_000 // ~1000 events at 1ms cursor spacing
export const MAX_AUTO_RECONNECT_ATTEMPTS = 12
export const HEARTBEAT_INTERVAL_MS = 30_000
export const BACKOFF_BASE_MS = 500
export const BACKOFF_CAP_MS = 30_000

export type RealtimeClientEvent =
  | { type: 'connected' }
  | { type: 'disconnected'; reason: string }
  | { type: 'feed_event'; event: FeedRealtimeEvent; latencyMs: number }
  | { type: 'gap_too_large'; signal: GapTooLargeSignal }
  | { type: 'manual_retry_required' }
  | { type: 'reconnecting'; attempt: number; delayMs: number }

export interface AppSyncRealtimeClientOptions {
  config: AppSyncEventsConfig
  lastCursor: number
  onEvent: (event: RealtimeClientEvent) => void
  webSocketFactory?: (url: string, protocols: string[]) => WebSocket
}

function base64UrlEncode(value: string): string {
  const bytes = new TextEncoder().encode(value)
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function buildAuthSubprotocol(config: AppSyncEventsConfig, sinceCursor?: number): string {
  const header: Record<string, string> = {
    host: config.httpHost,
    'x-api-key': config.apiKey,
  }
  if (sinceCursor && sinceCursor > 0) {
    header.since = String(sinceCursor)
  }
  return `header-${base64UrlEncode(JSON.stringify(header))}`
}

function parseFeedEvent(raw: unknown): FeedRealtimeEvent | null {
  if (!raw || typeof raw !== 'object') return null
  const event = raw as Partial<FeedRealtimeEvent>
  if (
    typeof event.eventId !== 'string' ||
    typeof event.recordId !== 'string' ||
    typeof event.summary !== 'string' ||
    typeof event.cursor !== 'number'
  ) {
    return null
  }
  return event as FeedRealtimeEvent
}

function estimateServerMs(cursor: number): number {
  return Math.floor(cursor / 1000)
}

export class AppSyncRealtimeClient {
  private readonly config: AppSyncEventsConfig
  private readonly onEvent: (event: RealtimeClientEvent) => void
  private readonly wsFactory: (url: string, protocols: string[]) => WebSocket

  private socket: WebSocket | null = null
  private subscriptionId: string | null = null
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private reconnectAttempt = 0
  private disposed = false
  private lastCursor: number
  private seenEventIds = new Set<string>()
  // ENC-TSK-L29: per-record `/records/{recordId}` subscriptions, multiplexed
  // on the same socket as the primary feed subscription. Keyed by the
  // client-chosen subscription id so incoming `data` frames route to the
  // right handler (matched via frame.id) instead of the global feed reducer.
  private extraSubscriptions = new Map<
    string,
    { channel: string; onEvent: (event: FeedRealtimeEvent) => void }
  >()

  constructor(options: AppSyncRealtimeClientOptions) {
    this.config = options.config
    this.onEvent = options.onEvent
    this.lastCursor = options.lastCursor
    this.wsFactory =
      options.webSocketFactory ??
      ((url, protocols) => new WebSocket(url, protocols))
  }

  start(): void {
    if (!this.config.enabled || this.disposed) return
    this.connect()
  }

  stop(): void {
    this.disposed = true
    this.clearTimers()
    if (this.socket) {
      this.socket.close()
      this.socket = null
    }
  }

  /** User-initiated retry resets backoff and reconnects immediately. */
  manualRetry(): void {
    if (this.disposed || !this.config.enabled) return
    this.reconnectAttempt = 0
    this.clearTimers()
    if (this.socket) {
      this.socket.close()
      this.socket = null
    }
    this.connect()
  }

  getLastCursor(): number {
    return this.lastCursor
  }

  /**
   * ENC-TSK-L29: subscribe to a single record's `/records/{recordId}` channel
   * on the SAME socket as the primary feed subscription. `onEvent` receives
   * only events for this record (full-body events per the backend contract).
   * Returns an unsubscribe function; safe to call even before the socket
   * connects (auto (re)subscribes once `connection_ack` arrives).
   */
  watchRecord(recordId: string, onEvent: (event: FeedRealtimeEvent) => void): () => void {
    const channel = `/records/${recordId}`
    const id = crypto.randomUUID()
    this.extraSubscriptions.set(id, { channel, onEvent })
    this.sendSubscribeFrame(id, channel)
    return () => {
      this.extraSubscriptions.delete(id)
      this.sendUnsubscribeFrame(id)
    }
  }

  private sendSubscribeFrame(id: string, channel: string): void {
    const socket = this.socket
    if (!socket || socket.readyState !== WebSocket.OPEN) return
    socket.send(
      JSON.stringify({
        type: 'subscribe',
        id,
        channel,
        authorization: { host: this.config.httpHost, 'x-api-key': this.config.apiKey },
      }),
    )
  }

  private sendUnsubscribeFrame(id: string): void {
    const socket = this.socket
    if (!socket || socket.readyState !== WebSocket.OPEN) return
    socket.send(JSON.stringify({ type: 'unsubscribe', id }))
  }

  private connect(): void {
    if (this.disposed || !this.config.enabled) return

    const url = `wss://${this.config.realtimeHost}/event/realtime`
    const protocols = ['aws-appsync-event-ws', buildAuthSubprotocol(this.config, this.lastCursor)]

    try {
      this.socket = this.wsFactory(url, protocols)
    } catch (error) {
      this.scheduleReconnect(`WebSocket constructor failed: ${String(error)}`)
      return
    }

    const socket = this.socket
    socket.onopen = () => {
      socket.send(JSON.stringify({ type: 'connection_init' }))
    }

    socket.onmessage = (message) => {
      this.handleMessage(message.data)
    }

    socket.onerror = () => {
      // onclose will handle reconnect scheduling.
    }

    socket.onclose = () => {
      this.clearHeartbeat()
      if (!this.disposed) {
        this.scheduleReconnect('socket closed')
      }
    }
  }

  private handleMessage(raw: unknown): void {
    if (typeof raw !== 'string') return

    let frame: { type?: string; id?: string; event?: unknown; errors?: unknown }
    try {
      frame = JSON.parse(raw) as { type?: string; id?: string; event?: unknown }
    } catch {
      return
    }

    if (frame.type === 'connection_ack') {
      this.reconnectAttempt = 0
      this.subscribe()
      // ENC-TSK-L29: re-establish any per-record watches after (re)connect —
      // AppSync subscriptions do not survive a socket replacement.
      for (const [id, sub] of this.extraSubscriptions) {
        this.sendSubscribeFrame(id, sub.channel)
      }
      this.startHeartbeat()
      this.onEvent({ type: 'connected' })
      return
    }

    if (frame.type === 'ka') {
      return
    }

    if (frame.type === 'error') {
      this.onEvent({ type: 'disconnected', reason: JSON.stringify(frame.errors ?? frame) })
      return
    }

    // ENC-TSK-L29: a data frame from a per-record subscription routes to that
    // watch's own handler — full-body events never touch the global feed
    // dedup/cursor/gap bookkeeping below, which is scoped to the primary
    // /feed/updates subscription.
    if (frame.type === 'data' && frame.event && frame.id && this.extraSubscriptions.has(frame.id)) {
      const sub = this.extraSubscriptions.get(frame.id)!
      try {
        const payload =
          typeof frame.event === 'string' ? (JSON.parse(frame.event) as unknown) : frame.event
        const feedEvent = parseFeedEvent(payload)
        if (feedEvent) sub.onEvent(feedEvent)
      } catch {
        // malformed per-record event — drop silently, same as the primary path
      }
      return
    }

    if (frame.type === 'data' && frame.event) {
      if (typeof frame.event === 'string') {
        try {
          const parsed = JSON.parse(frame.event) as { type?: string }
          if (parsed.type === 'gap_too_large') {
            this.onEvent({
              type: 'gap_too_large',
              signal: {
                type: 'gap_too_large',
                lastCursor: this.lastCursor,
                reason: 'server signaled gap_too_large',
              },
            })
            return
          }
        } catch {
          // fall through to feed event parse
        }
      }

      const payload =
        typeof frame.event === 'string' ? (JSON.parse(frame.event) as unknown) : frame.event
      const feedEvent = parseFeedEvent(payload)
      if (!feedEvent) return

      if (this.seenEventIds.has(feedEvent.eventId)) return
      this.seenEventIds.add(feedEvent.eventId)

      const gap = feedEvent.cursor - this.lastCursor
      if (this.lastCursor > 0 && gap > GAP_CURSOR_THRESHOLD) {
        this.onEvent({
          type: 'gap_too_large',
          signal: {
            type: 'gap_too_large',
            lastCursor: this.lastCursor,
            reason: `cursor gap ${gap} exceeds threshold`,
          },
        })
      }

      this.lastCursor = Math.max(this.lastCursor, feedEvent.cursor)
      const latencyMs = Math.max(0, Date.now() - estimateServerMs(feedEvent.cursor))
      this.onEvent({ type: 'feed_event', event: feedEvent, latencyMs })
    }
  }

  private subscribe(): void {
    const socket = this.socket
    if (!socket || socket.readyState !== WebSocket.OPEN) return

    this.subscriptionId = crypto.randomUUID()
    socket.send(
      JSON.stringify({
        type: 'subscribe',
        id: this.subscriptionId,
        channel: this.config.feedChannel,
        authorization: {
          host: this.config.httpHost,
          'x-api-key': this.config.apiKey,
          ...(this.lastCursor > 0 ? { since: String(this.lastCursor) } : {}),
        },
      }),
    )
  }

  private startHeartbeat(): void {
    this.clearHeartbeat()
    this.heartbeatTimer = setInterval(() => {
      if (this.socket?.readyState === WebSocket.OPEN) {
        this.socket.send(JSON.stringify({ type: 'ka' }))
      }
    }, HEARTBEAT_INTERVAL_MS)
  }

  private scheduleReconnect(reason: string): void {
    if (this.disposed) return

    this.reconnectAttempt += 1
    if (this.reconnectAttempt > MAX_AUTO_RECONNECT_ATTEMPTS) {
      this.onEvent({ type: 'manual_retry_required' })
      this.onEvent({ type: 'disconnected', reason: `manual retry required (${reason})` })
      return
    }

    const exp = Math.min(BACKOFF_CAP_MS, BACKOFF_BASE_MS * 2 ** (this.reconnectAttempt - 1))
    const jitter = 0.5 + Math.random() * 0.5
    const delayMs = Math.round(exp * jitter)

    this.onEvent({ type: 'reconnecting', attempt: this.reconnectAttempt, delayMs })
    this.clearTimers()
    this.reconnectTimer = setTimeout(() => this.connect(), delayMs)
  }

  private clearHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer)
      this.heartbeatTimer = null
    }
  }

  private clearTimers(): void {
    this.clearHeartbeat()
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
  }
}
