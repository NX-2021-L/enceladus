/**
 * ENC-TSK-N04 (B67 AC-18): offline queue engagement for tracker mutations.
 * navigator.onLine can report true while fetch fails at the network layer
 * (the W14-A forced-offline probe), so the queue must engage on a fetch
 * TypeError too — while real HTTP failures (4xx/5xx) must still throw.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'

vi.mock('../offline/mutationQueue', () => ({
  enqueueMutation: vi.fn(async (input: Record<string, unknown>) => ({
    ...input,
    id: 'queued-1',
    enqueuedAt: '2026-07-12T00:00:00.000Z',
  })),
}))
vi.mock('../store/offlineStore', () => ({
  useOfflineStore: {
    getState: () => ({ refreshPendingCount: vi.fn(async () => {}) }),
  },
}))

import { patchTrackerRecord } from './mutations'
import { enqueueMutation } from '../offline/mutationQueue'

describe('patchTrackerRecord offline queue (B67 AC-18)', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.clearAllMocks()
  })

  it('queues the mutation when fetch fails at the network layer despite navigator.onLine=true', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('Failed to fetch')
      }),
    )

    const result = await patchTrackerRecord('enceladus', 'task', 'ENC-TSK-1', {
      action: 'note',
      note: 'offline note',
    })

    expect(result.success).toBe(true)
    expect(result.record_id).toBe('ENC-TSK-1')
    expect(enqueueMutation).toHaveBeenCalledTimes(1)
    expect(vi.mocked(enqueueMutation).mock.calls[0][0]).toMatchObject({
      method: 'PATCH',
      body: { action: 'note', note: 'offline note' },
    })
  })

  it('does NOT queue on an HTTP error response', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify({ error: 'boom' }), { status: 500 })),
    )

    await expect(
      patchTrackerRecord('enceladus', 'task', 'ENC-TSK-1', { action: 'note', note: 'x' }),
    ).rejects.toThrow('boom')
    expect(enqueueMutation).not.toHaveBeenCalled()
  })

  it('queues without touching the network when navigator.onLine is false', async () => {
    const fetchSpy = vi.fn()
    vi.stubGlobal('fetch', fetchSpy)
    Object.defineProperty(window.navigator, 'onLine', { value: false, configurable: true })

    try {
      const result = await patchTrackerRecord('enceladus', 'task', 'ENC-TSK-2', {
        action: 'note',
        note: 'fully offline',
      })
      expect(result.success).toBe(true)
      expect(enqueueMutation).toHaveBeenCalledTimes(1)
      expect(fetchSpy).not.toHaveBeenCalled()
    } finally {
      Object.defineProperty(window.navigator, 'onLine', { value: true, configurable: true })
    }
  })
})
