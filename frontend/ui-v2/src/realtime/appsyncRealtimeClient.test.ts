import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  AppSyncRealtimeClient,
  BACKOFF_BASE_MS,
  BACKOFF_CAP_MS,
  GAP_CURSOR_THRESHOLD,
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
