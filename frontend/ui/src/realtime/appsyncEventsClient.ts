/**
 * AppSync Events WebSocket client (ENC-TSK-B67 AC-1, AC-4, AC-15, AC-23).
 *
 * A thin, dependency-injectable WebSocket subscriber for the AppSync Events
 * channel model (DOC-E470AC8CE9A8 §1.5):
 *   /feed/updates          global activity feed
 *   /records/{recordId}    record detail subscriptions
 *   /projects/{projectId}  project-scoped events
 *
 * Resilience (AC-4):
 *   - exponential backoff from 500ms, capped at 30s, 50-100% jitter
 *   - after 12 consecutive failed reconnects, surface a manual Retry button
 *   - 30s application-level heartbeat (ping) to detect half-open connections
 *   - on reconnect, send lastReceivedCursor; server replays missed events;
 *     a `gap_too_large` signal triggers an S3 snapshot re-fetch
 *
 * Concurrency (AC-15): every state-changing dispatch is routed through an
 * injected `scheduler` (React.startTransition in the app) so high-frequency
 * server pushes never block user input.
 *
 * The transport is intentionally abstracted behind `WebSocketLike` +
 * `createSocket` so the full reconnect/dedup/gap state machine is unit-testable
 * with a fake socket and fake timers, no live AWS required.
 */

import { parseFeedEvent, isGapTooLarge, type FeedEvent } from './eventModel'

export const BASE_RECONNECT_MS = 500
export const MAX_RECONNECT_MS = 30_000
export const HEARTBEAT_MS = 30_000
export const MANUAL_RETRY_THRESHOLD = 12
/** gap_too_large is signalled when the cursor gap exceeds this many events. */
export const GAP_THRESHOLD = 1000

export interface WebSocketLike {
  send(data: string): void
  close(): void
  onopen: ((ev?: unknown) => void) | null
  onclose: ((ev?: unknown) => void) | null
  onerror: ((ev?: unknown) => void) | null
  onmessage: ((ev: { data: unknown }) => void) | null
}

export type ConnectionStatus =
  | 'connecting'
  | 'open'
  | 'reconnecting'
  | 'manual_retry'
  | 'closed'

export interface AppSyncEventsClientOptions {
  channels: string[]
  createSocket: (channels: string[], sinceCursor: number | null) => WebSocketLike
  onEvent: (event: FeedEvent) => void
  /** Server signalled an oversize gap → caller should re-fetch the S3 snapshot. */
  onSnapshotRefetch?: () => void
  onStatusChange?: (status: ConnectionStatus) => void
  /** Wrap state-mutating dispatch (use React.startTransition). */
  scheduler?: (cb: () => void) => void
  /** Injectable timers + RNG for deterministic tests. */
  setTimeoutFn?: (cb: () => void, ms: number) => number
  clearTimeoutFn?: (id: number) => void
  random?: () => number
  getCursor?: () => number | null
}

export function computeBackoff(attempt: number, random: () => number = Math.random): number {
  // attempt is 1-based. Exponential from BASE, capped at MAX, then 50-100% jitter.
  const exp = BASE_RECONNECT_MS * Math.pow(2, Math.max(0, attempt - 1))
  const capped = Math.min(exp, MAX_RECONNECT_MS)
  const jitter = 0.5 + random() * 0.5 // [0.5, 1.0)
  return Math.round(capped * jitter)
}

export class AppSyncEventsClient {
  private opts: Required<
    Pick<
      AppSyncEventsClientOptions,
      'channels' | 'createSocket' | 'onEvent'
    >
  > &
    AppSyncEventsClientOptions
  private socket: WebSocketLike | null = null
  private status: ConnectionStatus = 'closed'
  private reconnectAttempts = 0
  private reconnectTimer: number | null = null
  private heartbeatTimer: number | null = null
  private lastReceivedCursor: number | null = null
  private stopped = false

  private readonly schedule: (cb: () => void) => void
  private readonly setT: (cb: () => void, ms: number) => number
  private readonly clearT: (id: number) => void
  private readonly rand: () => number

  constructor(options: AppSyncEventsClientOptions) {
    this.opts = options as typeof this.opts
    this.schedule = options.scheduler ?? ((cb) => cb())
    this.setT = options.setTimeoutFn ?? ((cb, ms) => setTimeout(cb, ms) as unknown as number)
    this.clearT = options.clearTimeoutFn ?? ((id) => clearTimeout(id))
    this.rand = options.random ?? Math.random
    if (options.getCursor) this.lastReceivedCursor = options.getCursor() ?? null
  }

  getStatus(): ConnectionStatus {
    return this.status
  }

  getLastCursor(): number | null {
    return this.lastReceivedCursor
  }

  getReconnectAttempts(): number {
    return this.reconnectAttempts
  }

  connect(): void {
    this.stopped = false
    this.openSocket('connecting')
  }

  /** Manual Retry button handler — resets the backoff counter and reconnects. */
  retry(): void {
    this.reconnectAttempts = 0
    this.clearReconnect()
    this.openSocket('connecting')
  }

  close(): void {
    this.stopped = true
    this.clearReconnect()
    this.clearHeartbeat()
    if (this.socket) {
      try {
        this.socket.close()
      } catch {
        /* ignore */
      }
      this.socket = null
    }
    this.setStatus('closed')
  }

  private openSocket(initialStatus: ConnectionStatus): void {
    this.setStatus(initialStatus)
    const socket = this.opts.createSocket(this.opts.channels, this.lastReceivedCursor)
    this.socket = socket

    socket.onopen = () => {
      this.reconnectAttempts = 0
      this.setStatus('open')
      this.startHeartbeat()
    }
    socket.onmessage = (ev) => this.handleMessage(ev.data)
    socket.onerror = () => {
      /* error precedes close; reconnection handled in onclose */
    }
    socket.onclose = () => {
      this.clearHeartbeat()
      if (this.stopped) return
      this.scheduleReconnect()
    }
  }

  private handleMessage(data: unknown): void {
    let parsed: unknown = data
    if (typeof data === 'string') {
      try {
        parsed = JSON.parse(data)
      } catch {
        return
      }
    }

    if (isGapTooLarge(parsed)) {
      this.schedule(() => this.opts.onSnapshotRefetch?.())
      return
    }

    const event = parseFeedEvent(parsed)
    if (!event) return

    // Gap detection on the live stream (defense in depth vs server signal).
    if (
      this.lastReceivedCursor !== null &&
      event.cursor - this.lastReceivedCursor > GAP_THRESHOLD
    ) {
      this.lastReceivedCursor = event.cursor
      this.schedule(() => this.opts.onSnapshotRefetch?.())
      return
    }

    this.lastReceivedCursor =
      this.lastReceivedCursor === null
        ? event.cursor
        : Math.max(this.lastReceivedCursor, event.cursor)

    this.schedule(() => this.opts.onEvent(event))
  }

  private scheduleReconnect(): void {
    this.reconnectAttempts += 1
    if (this.reconnectAttempts >= MANUAL_RETRY_THRESHOLD) {
      this.setStatus('manual_retry')
      return
    }
    this.setStatus('reconnecting')
    const delay = computeBackoff(this.reconnectAttempts, this.rand)
    this.reconnectTimer = this.setT(() => {
      if (this.stopped) return
      this.openSocket('reconnecting')
    }, delay)
  }

  private startHeartbeat(): void {
    this.clearHeartbeat()
    const tick = () => {
      if (this.stopped || !this.socket) return
      try {
        this.socket.send(JSON.stringify({ type: 'ping', ts: Date.now() }))
      } catch {
        /* ignore — onclose will trigger reconnect */
      }
      this.heartbeatTimer = this.setT(tick, HEARTBEAT_MS)
    }
    this.heartbeatTimer = this.setT(tick, HEARTBEAT_MS)
  }

  private clearHeartbeat(): void {
    if (this.heartbeatTimer !== null) {
      this.clearT(this.heartbeatTimer)
      this.heartbeatTimer = null
    }
  }

  private clearReconnect(): void {
    if (this.reconnectTimer !== null) {
      this.clearT(this.reconnectTimer)
      this.reconnectTimer = null
    }
  }

  private setStatus(status: ConnectionStatus): void {
    if (this.status === status) return
    this.status = status
    this.opts.onStatusChange?.(status)
  }
}
