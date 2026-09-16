import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { subscribeToRecordChannel } from './appsyncRecordChannel'

class FakeWebSocket {
  static instances: FakeWebSocket[] = []
  sent: string[] = []
  onopen: (() => void) | null = null
  onmessage: ((ev: { data: string }) => void) | null = null
  onclose: (() => void) | null = null
  onerror: (() => void) | null = null

  constructor(
    public url: string,
    public protocols: string[],
  ) {
    FakeWebSocket.instances.push(this)
  }

  send(data: string) {
    this.sent.push(data)
  }

  close() {
    this.onclose?.()
  }

  triggerOpen() {
    this.onopen?.()
  }

  triggerMessage(payload: unknown) {
    this.onmessage?.({ data: JSON.stringify(payload) })
  }
}

function factory() {
  return (url: string, protocols: string[]) =>
    new FakeWebSocket(url, protocols) as unknown as WebSocket
}

describe('subscribeToRecordChannel', () => {
  beforeEach(() => {
    FakeWebSocket.instances = []
    // Bare hosts, no protocol prefix — matches how ui-v2's appsyncConfig.ts
    // (same stripProtocol contract) expects these vars to be set; the code
    // prepends wss:// itself when building the realtime URL.
    vi.stubEnv('VITE_APPSYNC_HTTP_HOST', 'api.example.com')
    vi.stubEnv('VITE_APPSYNC_REALTIME_HOST', 'realtime.example.com')
    vi.stubEnv('VITE_APPSYNC_API_KEY', 'key-123')
  })

  afterEach(() => {
    vi.unstubAllEnvs()
  })

  it('is a no-op when AppSync env vars are unset (frontend/ui has none wired yet)', () => {
    vi.stubEnv('VITE_APPSYNC_HTTP_HOST', '')
    const onStatusChange = vi.fn()
    const unsubscribe = subscribeToRecordChannel({
      documentId: 'DOC-ABC',
      onEvent: vi.fn(),
      onStatusChange,
      webSocketFactory: factory(),
    })
    expect(onStatusChange).toHaveBeenCalledWith('disconnected')
    expect(FakeWebSocket.instances).toHaveLength(0)
    unsubscribe()
  })

  it('completes the handshake and subscribes to /records/{documentId}', () => {
    const onStatusChange = vi.fn()
    subscribeToRecordChannel({
      documentId: 'DOC-ABC',
      onEvent: vi.fn(),
      onStatusChange,
      webSocketFactory: factory(),
    })

    const ws = FakeWebSocket.instances[0]!
    expect(ws.url).toBe('wss://realtime.example.com/event/realtime')
    expect(ws.protocols[0]).toBe('aws-appsync-event-ws')

    ws.triggerOpen()
    expect(JSON.parse(ws.sent[0]!)).toEqual({ type: 'connection_init' })

    ws.triggerMessage({ type: 'connection_ack', connectionTimeoutMs: 300000 })
    expect(onStatusChange).toHaveBeenCalledWith('connected')

    const subscribeFrame = JSON.parse(ws.sent[1]!)
    expect(subscribeFrame.type).toBe('subscribe')
    expect(subscribeFrame.channel).toBe('/records/DOC-ABC')
    expect(subscribeFrame.authorization).toEqual({
      host: 'api.example.com',
      'x-api-key': 'key-123',
    })
  })

  it('delivers data frame events (K29 full-record-body) to onEvent', () => {
    const onEvent = vi.fn()
    subscribeToRecordChannel({
      documentId: 'DOC-ABC',
      onEvent,
      webSocketFactory: factory(),
    })
    const ws = FakeWebSocket.instances[0]!
    ws.triggerOpen()
    ws.triggerMessage({ type: 'connection_ack' })

    ws.triggerMessage({
      type: 'data',
      id: 'sub-1',
      event: JSON.stringify({
        eventId: 'evt-1',
        recordId: 'DOC-ABC',
        record: { title: 'New title' },
      }),
    })

    expect(onEvent).toHaveBeenCalledWith(
      expect.objectContaining({ eventId: 'evt-1', record: { title: 'New title' } }),
    )
  })

  it('ignores keepalive and error frames', () => {
    const onEvent = vi.fn()
    subscribeToRecordChannel({
      documentId: 'DOC-ABC',
      onEvent,
      webSocketFactory: factory(),
    })
    const ws = FakeWebSocket.instances[0]!
    ws.triggerOpen()
    ws.triggerMessage({ type: 'ka' })
    ws.triggerMessage({ type: 'error', id: 'sub-1', errors: ['boom'] })
    expect(onEvent).not.toHaveBeenCalled()
  })

  it('drops malformed data frames silently instead of throwing', () => {
    const onEvent = vi.fn()
    subscribeToRecordChannel({
      documentId: 'DOC-ABC',
      onEvent,
      webSocketFactory: factory(),
    })
    const ws = FakeWebSocket.instances[0]!
    ws.triggerOpen()
    expect(() => ws.triggerMessage({ type: 'data', id: 'sub-1', event: '{not json' })).not.toThrow()
    expect(onEvent).not.toHaveBeenCalled()
  })

  it('unsubscribe closes the socket and stops further status updates', () => {
    const onStatusChange = vi.fn()
    const unsubscribe = subscribeToRecordChannel({
      documentId: 'DOC-ABC',
      onEvent: vi.fn(),
      onStatusChange,
      webSocketFactory: factory(),
    })
    const ws = FakeWebSocket.instances[0]!
    ws.triggerOpen()
    onStatusChange.mockClear()

    unsubscribe()
    expect(onStatusChange).not.toHaveBeenCalled()
  })
})
