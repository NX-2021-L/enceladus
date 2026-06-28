import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  AppSyncEventsClient,
  computeBackoff,
  BASE_RECONNECT_MS,
  MAX_RECONNECT_MS,
  MANUAL_RETRY_THRESHOLD,
  type WebSocketLike,
} from './appsyncEventsClient'

class FakeSocket implements WebSocketLike {
  onopen: ((ev?: unknown) => void) | null = null
  onclose: ((ev?: unknown) => void) | null = null
  onerror: ((ev?: unknown) => void) | null = null
  onmessage: ((ev: { data: unknown }) => void) | null = null
  sent: string[] = []
  closed = false
  send(data: string) {
    this.sent.push(data)
  }
  close() {
    this.closed = true
    this.onclose?.()
  }
  emit(data: unknown) {
    this.onmessage?.({ data })
  }
}

const validEvent = (cursor: number, eventId?: string) => ({
  eventId: eventId ?? `0190a1b2-c3d4-7e5f-8a9b-${cursor.toString(16).padStart(12, '0')}`,
  recordId: 'ENC-TSK-B67',
  record_type: 'task',
  action: 'updated',
  actorType: 'agent',
  actorId: 'ENC-SES-003',
  summary: 's',
  cursor,
})

describe('computeBackoff (AC-4)', () => {
  it('starts at ~500ms and grows exponentially within jitter band', () => {
    const noJitter = () => 1 // jitter factor → 1.0 (max of band)
    expect(computeBackoff(1, noJitter)).toBe(BASE_RECONNECT_MS)
    expect(computeBackoff(2, noJitter)).toBe(BASE_RECONNECT_MS * 2)
    expect(computeBackoff(3, noJitter)).toBe(BASE_RECONNECT_MS * 4)
  })

  it('caps at 30s', () => {
    expect(computeBackoff(20, () => 1)).toBe(MAX_RECONNECT_MS)
  })

  it('applies 50-100% jitter', () => {
    expect(computeBackoff(1, () => 0)).toBe(BASE_RECONNECT_MS * 0.5)
    expect(computeBackoff(1, () => 0.999)).toBeGreaterThan(BASE_RECONNECT_MS * 0.74)
  })
})

describe('AppSyncEventsClient', () => {
  let sockets: FakeSocket[]
  let onEvent: ReturnType<typeof vi.fn>
  let onSnapshotRefetch: ReturnType<typeof vi.fn>
  let timers: Array<{ cb: () => void; ms: number; id: number }>
  let nextId: number

  const flushTimer = (id: number) => {
    const t = timers.find((x) => x.id === id)
    if (t) t.cb()
  }

  const makeClient = (channels = ['/feed/updates']) =>
    new AppSyncEventsClient({
      channels,
      createSocket: () => {
        const s = new FakeSocket()
        sockets.push(s)
        return s
      },
      onEvent,
      onSnapshotRefetch,
      setTimeoutFn: (cb, ms) => {
        const id = nextId++
        timers.push({ cb, ms, id })
        return id
      },
      clearTimeoutFn: (id) => {
        timers = timers.filter((t) => t.id !== id)
      },
      random: () => 1,
    })

  beforeEach(() => {
    sockets = []
    timers = []
    nextId = 1
    onEvent = vi.fn()
    onSnapshotRefetch = vi.fn()
  })

  afterEach(() => vi.restoreAllMocks())

  it('connects and dispatches a valid event', () => {
    const c = makeClient()
    c.connect()
    sockets[0].onopen?.()
    expect(c.getStatus()).toBe('open')
    sockets[0].emit(JSON.stringify(validEvent(5)))
    expect(onEvent).toHaveBeenCalledTimes(1)
    expect(c.getLastCursor()).toBe(5)
  })

  it('drops malformed frames', () => {
    const c = makeClient()
    c.connect()
    sockets[0].onopen?.()
    sockets[0].emit('{ not json')
    sockets[0].emit(JSON.stringify({ foo: 'bar' }))
    expect(onEvent).not.toHaveBeenCalled()
  })

  it('reconnects with backoff on close and resets attempts on open', () => {
    const c = makeClient()
    c.connect()
    sockets[0].onopen?.()
    sockets[0].onclose?.() // disconnect
    expect(c.getStatus()).toBe('reconnecting')
    expect(c.getReconnectAttempts()).toBe(1)
    // a reconnect timer was scheduled
    const timer = timers[timers.length - 1]
    expect(timer.ms).toBe(BASE_RECONNECT_MS)
    flushTimer(timer.id)
    expect(sockets).toHaveLength(2)
    sockets[1].onopen?.()
    expect(c.getReconnectAttempts()).toBe(0)
  })

  it('surfaces manual_retry after 12 failed reconnects', () => {
    const c = makeClient()
    c.connect()
    // simulate 12 consecutive close events without opening
    for (let i = 0; i < MANUAL_RETRY_THRESHOLD; i++) {
      const sock = sockets[sockets.length - 1]
      sock.onclose?.()
      const t = timers[timers.length - 1]
      if (c.getStatus() === 'manual_retry') break
      flushTimer(t.id)
    }
    expect(c.getStatus()).toBe('manual_retry')
  })

  it('retry() resets the backoff and reconnects', () => {
    const c = makeClient()
    c.connect()
    for (let i = 0; i < MANUAL_RETRY_THRESHOLD; i++) {
      sockets[sockets.length - 1].onclose?.()
      const t = timers[timers.length - 1]
      if (c.getStatus() === 'manual_retry') break
      flushTimer(t.id)
    }
    expect(c.getStatus()).toBe('manual_retry')
    c.retry()
    expect(c.getReconnectAttempts()).toBe(0)
  })

  it('triggers S3 snapshot refetch on gap_too_large signal (AC-4)', () => {
    const c = makeClient()
    c.connect()
    sockets[0].onopen?.()
    sockets[0].emit(JSON.stringify({ type: 'gap_too_large', lastReceivedCursor: 3 }))
    expect(onSnapshotRefetch).toHaveBeenCalledTimes(1)
    expect(onEvent).not.toHaveBeenCalled()
  })

  it('triggers snapshot refetch when the live cursor gap exceeds threshold', () => {
    const c = makeClient()
    c.connect()
    sockets[0].onopen?.()
    sockets[0].emit(JSON.stringify(validEvent(1)))
    sockets[0].emit(JSON.stringify(validEvent(5000)))
    expect(onSnapshotRefetch).toHaveBeenCalledTimes(1)
  })

  it('sends a heartbeat ping after the heartbeat interval', () => {
    const c = makeClient()
    c.connect()
    sockets[0].onopen?.()
    const hb = timers[timers.length - 1]
    flushTimer(hb.id)
    expect(sockets[0].sent.some((m) => m.includes('ping'))).toBe(true)
  })

  it('stops reconnecting after close()', () => {
    const c = makeClient()
    c.connect()
    sockets[0].onopen?.()
    c.close()
    sockets[0].onclose?.()
    expect(c.getStatus()).toBe('closed')
  })
})
