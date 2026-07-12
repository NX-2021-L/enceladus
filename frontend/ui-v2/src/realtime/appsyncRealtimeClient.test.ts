import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  AppSyncRealtimeClient,
  BACKOFF_BASE_MS,
  BACKOFF_CAP_MS,
  GAP_CURSOR_THRESHOLD,
  LIVENESS_CHECK_INTERVAL_MS,
  MAX_AUTO_RECONNECT_ATTEMPTS,
} from './appsyncRealtimeClient'
import type { AppSyncEventsConfig } from '../api/appsyncConfig'

class MockWebSocket {
  static instances: MockWebSocket[] = []
  static OPEN = 1

  readyState = MockWebSocket.OPEN
  onopen: (() => void) | null = null
  onmessage: ((event: { data: string }) => void) | null = null
  onerror: (() => void) | null = null
  onclose: (() => void) | null = null
  sent: string[] = []

  constructor(_url: string, _protocols: string[]) {
    MockWebSocket.instances.push(this)
  }

  send(data: string) {
    this.sent.push(data)
  }

  close() {
    this.readyState = 3
    this.onclose?.()
  }

  emit(data: unknown) {
    this.onmessage?.({ data: JSON.stringify(data) })
  }

  open() {
    this.onopen?.()
  }
}

const config: AppSyncEventsConfig = {
  httpHost: 'abc.appsync-api.us-west-2.amazonaws.com',
  realtimeHost: 'abc.appsync-realtime-api.us-west-2.amazonaws.com',
  apiKey: 'test-key',
  region: 'us-west-2',
  feedChannel: '/feed/updates',
  enabled: true,
}

describe('AppSyncRealtimeClient', () => {
  afterEach(() => {
    vi.useRealTimers()
    MockWebSocket.instances = []
  })

  it('sends connection_init then subscribes on connection_ack', () => {
    const events: string[] = []
    const client = new AppSyncRealtimeClient({
      config,
      lastCursor: 0,
      onEvent: (event) => events.push(event.type),
      webSocketFactory: (url, protocols) => new MockWebSocket(url, protocols) as unknown as WebSocket,
    })

    client.start()
    const socket = MockWebSocket.instances[0]
    socket.open()
    expect(socket.sent.some((msg) => msg.includes('connection_init'))).toBe(true)

    socket.emit({ type: 'connection_ack' })
    expect(socket.sent.some((msg) => msg.includes('subscribe'))).toBe(true)
    expect(events).toContain('connected')
    client.stop()
  })

  it('deduplicates feed events by eventId', () => {
    const received: number[] = []
    const client = new AppSyncRealtimeClient({
      config,
      lastCursor: 0,
      onEvent: (event) => {
        if (event.type === 'feed_event') received.push(event.event.cursor)
      },
      webSocketFactory: (url, protocols) => new MockWebSocket(url, protocols) as unknown as WebSocket,
    })

    client.start()
    const socket = MockWebSocket.instances[0]
    socket.open()
    socket.emit({ type: 'connection_ack' })

    const payload = {
      eventId: 'evt-1',
      recordId: 'ENC-TSK-1',
      record_type: 'task',
      action: 'updated',
      actorType: 'agent',
      actorId: 'ENC-SES-1',
      summary: 'updated task',
      cursor: 1_700_000_000_000,
      channels: ['/feed/updates'],
    }

    socket.emit({ type: 'data', event: JSON.stringify(payload) })
    socket.emit({ type: 'data', event: JSON.stringify(payload) })
    expect(received).toEqual([1_700_000_000_000])
    client.stop()
  })

  it('requires manual retry after max reconnect attempts', () => {
    vi.useFakeTimers()
    const phases: string[] = []
    const client = new AppSyncRealtimeClient({
      config,
      lastCursor: 0,
      onEvent: (event) => phases.push(event.type),
      webSocketFactory: (url, protocols) => new MockWebSocket(url, protocols) as unknown as WebSocket,
    })

    client.start()
    for (let i = 0; i <= MAX_AUTO_RECONNECT_ATTEMPTS; i++) {
      MockWebSocket.instances.at(-1)?.close()
      vi.advanceTimersByTime(BACKOFF_CAP_MS)
    }

    expect(phases).toContain('manual_retry_required')
    client.stop()
  })

  // ENC-TSK-N04 (B67 AC-4): the provider maps events 1:1 onto phases, so
  // manual_retry_required must be the LAST event of the terminal sequence —
  // the old order emitted 'disconnected' after it, clobbering the
  // manual_retry phase and hiding the Retry affordance (W14-A silent halt).
  it('emits manual_retry_required as the final terminal event, after disconnected', () => {
    vi.useFakeTimers()
    const events: string[] = []
    const client = new AppSyncRealtimeClient({
      config,
      lastCursor: 0,
      onEvent: (event) => events.push(event.type),
      webSocketFactory: (url, protocols) => new MockWebSocket(url, protocols) as unknown as WebSocket,
    })

    client.start()
    for (let i = 0; i <= MAX_AUTO_RECONNECT_ATTEMPTS; i++) {
      MockWebSocket.instances.at(-1)?.close()
      vi.advanceTimersByTime(BACKOFF_CAP_MS)
    }

    expect(events.at(-1)).toBe('manual_retry_required')
    expect(events.at(-2)).toBe('disconnected')
    client.stop()
  })

  // ENC-TSK-N04 (B67 AC-4): visibility/online re-kicks must not reset the
  // backoff counter — W14-A observed the sequence restarting from attempt 1
  // mid-outage (refocus fired manualRetry), which also kept the 12-attempt
  // Retry bar forever out of reach under tab churn.
  it('livenessKick reconnects immediately without resetting the attempt counter', () => {
    vi.useFakeTimers()
    const attempts: number[] = []
    const client = new AppSyncRealtimeClient({
      config,
      lastCursor: 0,
      onEvent: (event) => {
        if (event.type === 'reconnecting') attempts.push(event.attempt)
      },
      webSocketFactory: (url, protocols) => new MockWebSocket(url, protocols) as unknown as WebSocket,
    })

    client.start()
    MockWebSocket.instances.at(-1)?.close() // attempt 1 scheduled
    vi.advanceTimersByTime(BACKOFF_CAP_MS)
    MockWebSocket.instances.at(-1)?.close() // attempt 2 scheduled

    client.livenessKick() // immediate reconnect, counter preserved
    MockWebSocket.instances.at(-1)?.close() // fails again -> attempt 3, not 1

    expect(attempts).toEqual([1, 2, 3])

    client.manualRetry() // user-clicked Retry DOES reset
    MockWebSocket.instances.at(-1)?.close()
    expect(attempts).toEqual([1, 2, 3, 1])
    client.stop()
  })

  it('livenessKick is a no-op while the socket is open', () => {
    const client = new AppSyncRealtimeClient({
      config,
      lastCursor: 0,
      onEvent: () => {},
      webSocketFactory: (url, protocols) => new MockWebSocket(url, protocols) as unknown as WebSocket,
    })

    client.start()
    expect(MockWebSocket.instances).toHaveLength(1)
    client.livenessKick() // mock sockets report OPEN
    expect(MockWebSocket.instances).toHaveLength(1)
    client.stop()
  })

  it('emits gap_too_large when cursor jump exceeds threshold', () => {
    let gap = false
    const client = new AppSyncRealtimeClient({
      config,
      lastCursor: 1,
      onEvent: (event) => {
        if (event.type === 'gap_too_large') gap = true
      },
      webSocketFactory: (url, protocols) => new MockWebSocket(url, protocols) as unknown as WebSocket,
    })

    client.start()
    const socket = MockWebSocket.instances[0]
    socket.open()
    socket.emit({ type: 'connection_ack' })
    socket.emit({
      type: 'data',
      event: JSON.stringify({
        eventId: 'evt-gap',
        recordId: 'ENC-TSK-9',
        record_type: 'task',
        action: 'updated',
        actorType: 'agent',
        actorId: 'ENC-SES-9',
        summary: 'gap',
        cursor: 1 + GAP_CURSOR_THRESHOLD + 1,
        channels: ['/feed/updates'],
      }),
    })

    expect(gap).toBe(true)
    client.stop()
  })
})

describe('AppSyncRealtimeClient — realtime channel protocol compliance (ENC-TSK-M96)', () => {
  afterEach(() => {
    vi.useRealTimers()
    MockWebSocket.instances = []
  })

  function newClient(onEvent: (type: string) => void = () => {}, lastCursor = 0) {
    const client = new AppSyncRealtimeClient({
      config,
      lastCursor,
      onEvent: (event) => onEvent(event.type),
      webSocketFactory: (url, protocols) => new MockWebSocket(url, protocols) as unknown as WebSocket,
    })
    client.start()
    const socket = MockWebSocket.instances.at(-1)!
    socket.open()
    socket.emit({ type: 'connection_ack', connectionTimeoutMs: 300_000 })
    return { client, socket }
  }

  it('never sends a client ka frame — AppSync Events rejects it with UnsupportedOperation', () => {
    vi.useFakeTimers()
    const { client, socket } = newClient()

    vi.advanceTimersByTime(10 * 60_000)
    const kaFrames = socket.sent.map((raw) => JSON.parse(raw)).filter((f) => f.type === 'ka')
    expect(kaFrames).toEqual([])
    client.stop()
  })

  it('id-less error frames (operation-level rejections) do not downgrade the transport', () => {
    const events: string[] = []
    const { client, socket } = newClient((t) => events.push(t))

    socket.emit({
      type: 'error',
      errors: [
        {
          errorType: 'UnsupportedOperation',
          message: 'Operation not supported through the realtime channel',
        },
      ],
    })
    expect(events).not.toContain('disconnected')

    // The subscription is still live: a subsequent data frame must deliver.
    socket.emit({
      type: 'data',
      event: JSON.stringify({
        eventId: 'evt-after-error',
        recordId: 'ENC-TSK-1',
        record_type: 'task',
        action: 'updated',
        actorType: 'agent',
        actorId: 'ENC-SES-1',
        summary: 'updated task',
        cursor: 1_700_000_000_000,
        channels: ['/feed/updates'],
      }),
    })
    expect(events).toContain('feed_event')
    client.stop()
  })

  it('an error naming the primary subscription id still disconnects', () => {
    const events: string[] = []
    const { client, socket } = newClient((t) => events.push(t))

    const subscribeFrame = socket.sent
      .map((raw) => JSON.parse(raw))
      .find((f) => f.type === 'subscribe' && f.channel === '/feed/updates')
    socket.emit({ type: 'error', id: subscribeFrame.id, errors: [{ errorType: 'Unauthorized' }] })
    expect(events).toContain('disconnected')
    client.stop()
  })

  it('forces a reconnect when the server blows the connectionTimeoutMs ka window', () => {
    vi.useFakeTimers()
    const events: string[] = []
    const client = new AppSyncRealtimeClient({
      config,
      lastCursor: 0,
      onEvent: (event) => events.push(event.type),
      webSocketFactory: (url, protocols) => new MockWebSocket(url, protocols) as unknown as WebSocket,
    })
    client.start()
    const socket = MockWebSocket.instances[0]
    socket.open()
    socket.emit({ type: 'connection_ack', connectionTimeoutMs: 1_000 })

    vi.advanceTimersByTime(LIVENESS_CHECK_INTERVAL_MS + 1_000)
    expect(socket.readyState).toBe(3)
    expect(events).toContain('reconnecting')
    client.stop()
  })

  it('keeps the server-silence watchdog fed by incoming ka frames', () => {
    vi.useFakeTimers()
    const events: string[] = []
    const client = new AppSyncRealtimeClient({
      config,
      lastCursor: 0,
      onEvent: (event) => events.push(event.type),
      webSocketFactory: (url, protocols) => new MockWebSocket(url, protocols) as unknown as WebSocket,
    })
    client.start()
    const socket = MockWebSocket.instances[0]
    socket.open()
    socket.emit({ type: 'connection_ack', connectionTimeoutMs: 60_000 })

    for (let i = 0; i < 8; i++) {
      vi.advanceTimersByTime(30_000)
      socket.emit({ type: 'ka' })
    }
    expect(socket.readyState).toBe(MockWebSocket.OPEN)
    expect(events).not.toContain('reconnecting')
    client.stop()
  })

  it("a replaced socket's late close does not tear down the live connection (manualRetry)", () => {
    const events: string[] = []
    const { client, socket: first } = newClient((t) => events.push(t))
    expect(events).toEqual(['connected'])

    // manualRetry discards the first socket (its close fires synchronously in
    // the mock — the worst-case ordering) and dials a second one.
    client.manualRetry()
    const second = MockWebSocket.instances.at(-1)!
    expect(second).not.toBe(first)
    second.open()
    second.emit({ type: 'connection_ack', connectionTimeoutMs: 300_000 })

    // The abandoned socket's close must not have scheduled a rival reconnect.
    expect(events).toEqual(['connected', 'connected'])
    const subscribed = second.sent
      .map((raw) => JSON.parse(raw))
      .some((f) => f.type === 'subscribe' && f.channel === '/feed/updates')
    expect(subscribed).toBe(true)
    client.stop()
  })

  it('ignores frames from a socket that has been replaced', () => {
    const events: string[] = []
    const { client, socket: first } = newClient((t) => events.push(t))

    client.manualRetry()
    // A zombie ack from the abandoned socket must not subscribe anything.
    first.readyState = MockWebSocket.OPEN
    first.emit({ type: 'connection_ack', connectionTimeoutMs: 300_000 })
    expect(events.filter((t) => t === 'connected')).toHaveLength(1)
    client.stop()
  })
})

describe('AppSyncRealtimeClient — per-record watch (ENC-TSK-L29)', () => {
  afterEach(() => {
    MockWebSocket.instances = []
  })

  it('subscribes to /records/{recordId} and routes matching data frames to the watch handler only', () => {
    const globalEvents: string[] = []
    const client = new AppSyncRealtimeClient({
      config,
      lastCursor: 0,
      onEvent: (event) => globalEvents.push(event.type),
      webSocketFactory: (url, protocols) => new MockWebSocket(url, protocols) as unknown as WebSocket,
    })

    client.start()
    const socket = MockWebSocket.instances[0]
    socket.open()
    socket.emit({ type: 'connection_ack' })

    const recordEvents: unknown[] = []
    client.watchRecord('ENC-TSK-L29T', (event) => recordEvents.push(event))

    const subscribeFrame = socket.sent
      .map((raw) => JSON.parse(raw))
      .find((frame) => frame.type === 'subscribe' && frame.channel === '/records/ENC-TSK-L29T')
    expect(subscribeFrame).toBeDefined()

    const detailPayload = {
      eventId: 'evt-detail-1',
      recordId: 'ENC-TSK-L29T',
      record_type: 'task',
      action: 'updated',
      actorType: 'agent',
      actorId: 'ENC-SES-1',
      summary: 'updated task',
      cursor: 1_700_000_000_001,
      channels: ['/records/ENC-TSK-L29T'],
      record: { item_id: 'ENC-TSK-L29T', title: 'Full body' },
    }
    socket.emit({ type: 'data', id: subscribeFrame.id, event: JSON.stringify(detailPayload) })

    expect(recordEvents).toHaveLength(1)
    expect((recordEvents[0] as { record?: { title?: string } }).record?.title).toBe('Full body')
    // Per-record events never reach the global feed_event handler.
    expect(globalEvents).not.toContain('feed_event')
    client.stop()
  })

  it('unsubscribe stops routing further events and sends an unsubscribe frame', () => {
    const client = new AppSyncRealtimeClient({
      config,
      lastCursor: 0,
      onEvent: () => {},
      webSocketFactory: (url, protocols) => new MockWebSocket(url, protocols) as unknown as WebSocket,
    })

    client.start()
    const socket = MockWebSocket.instances[0]
    socket.open()
    socket.emit({ type: 'connection_ack' })

    const recordEvents: unknown[] = []
    const unsubscribe = client.watchRecord('ENC-TSK-L29T', (event) => recordEvents.push(event))
    const subscribeFrame = socket.sent
      .map((raw) => JSON.parse(raw))
      .find((frame) => frame.type === 'subscribe' && frame.channel === '/records/ENC-TSK-L29T')

    unsubscribe()
    expect(
      socket.sent.map((raw) => JSON.parse(raw)).some((f) => f.type === 'unsubscribe' && f.id === subscribeFrame.id),
    ).toBe(true)

    socket.emit({
      type: 'data',
      id: subscribeFrame.id,
      event: JSON.stringify({
        eventId: 'evt-detail-2',
        recordId: 'ENC-TSK-L29T',
        record_type: 'task',
        action: 'updated',
        actorType: 'agent',
        actorId: 'ENC-SES-1',
        summary: 'updated task',
        cursor: 1_700_000_000_002,
        channels: ['/records/ENC-TSK-L29T'],
        record: { item_id: 'ENC-TSK-L29T' },
      }),
    })
    expect(recordEvents).toHaveLength(0)
    client.stop()
  })

  it('resubscribes watched records after a reconnect', () => {
    vi.useFakeTimers()
    const client = new AppSyncRealtimeClient({
      config,
      lastCursor: 0,
      onEvent: () => {},
      webSocketFactory: (url, protocols) => new MockWebSocket(url, protocols) as unknown as WebSocket,
    })

    client.start()
    let socket = MockWebSocket.instances[0]
    socket.open()
    socket.emit({ type: 'connection_ack' })
    client.watchRecord('ENC-TSK-L29T', () => {})

    socket.close()
    vi.advanceTimersByTime(BACKOFF_BASE_MS * 4)
    socket = MockWebSocket.instances.at(-1)!
    socket.open()
    socket.emit({ type: 'connection_ack' })

    const resubscribed = socket.sent
      .map((raw) => JSON.parse(raw))
      .some((frame) => frame.type === 'subscribe' && frame.channel === '/records/ENC-TSK-L29T')
    expect(resubscribed).toBe(true)
    client.stop()
  })
})
