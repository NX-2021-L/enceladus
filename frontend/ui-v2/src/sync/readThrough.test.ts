import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchDocumentRecord, fetchTrackerRecord } from '../api/client'
import { resetCacheEngineForTests } from './cacheEngine'
import { readThroughDocumentRecord, readThroughTrackerRecord } from './readThrough'

vi.mock('../api/client', () => ({
  // Real class so `error instanceof SessionExpiredError` works in readThrough.
  SessionExpiredError: class SessionExpiredError extends Error {},
  fetchTrackerRecord: vi.fn(),
  fetchDocumentRecord: vi.fn(),
}))

describe('readThrough fetchers (ENC-TSK-M51: network-first detail reads)', () => {
  beforeEach(() => {
    resetCacheEngineForTests()
    vi.mocked(fetchTrackerRecord).mockReset()
    vi.mocked(fetchDocumentRecord).mockReset()
  })

  it('issues a real per-record GET on every load, even when tier2 has a copy', async () => {
    vi.mocked(fetchTrackerRecord)
      .mockResolvedValueOnce({ record_id: 'ENC-TSK-1', updated_at: '1' })
      .mockResolvedValueOnce({ record_id: 'ENC-TSK-1', updated_at: '2' })

    const first = await readThroughTrackerRecord('task', 'enceladus', 'ENC-TSK-1')
    const second = await readThroughTrackerRecord('task', 'enceladus', 'ENC-TSK-1')

    // The second load reflects the newer server body — it did NOT serve the
    // tier2 mirror seeded by the first fetch (that was the M51 defect).
    expect(first).toEqual({ record_id: 'ENC-TSK-1', updated_at: '1' })
    expect(second).toEqual({ record_id: 'ENC-TSK-1', updated_at: '2' })
    expect(fetchTrackerRecord).toHaveBeenCalledTimes(2)
  })

  it('falls back to the tier2 mirror when the network read fails (offline degrade)', async () => {
    vi.mocked(fetchTrackerRecord).mockResolvedValueOnce({ record_id: 'ENC-TSK-2', updated_at: '5' })
    await readThroughTrackerRecord('task', 'enceladus', 'ENC-TSK-2')

    vi.mocked(fetchTrackerRecord).mockRejectedValueOnce(new Error('network down'))
    const degraded = await readThroughTrackerRecord('task', 'enceladus', 'ENC-TSK-2')
    expect(degraded).toEqual({ record_id: 'ENC-TSK-2', updated_at: '5' })
  })

  it('propagates a network error when there is no mirror to fall back to', async () => {
    vi.mocked(fetchTrackerRecord).mockRejectedValueOnce(new Error('network down'))
    await expect(readThroughTrackerRecord('task', 'enceladus', 'ENC-TSK-3')).rejects.toThrow(
      'network down',
    )
  })

  it('does not serve stale on an aborted load', async () => {
    vi.mocked(fetchTrackerRecord).mockResolvedValueOnce({ record_id: 'ENC-TSK-4', updated_at: '5' })
    await readThroughTrackerRecord('task', 'enceladus', 'ENC-TSK-4') // seed mirror

    const controller = new AbortController()
    controller.abort()
    vi.mocked(fetchTrackerRecord).mockRejectedValueOnce(new Error('aborted'))
    await expect(
      readThroughTrackerRecord('task', 'enceladus', 'ENC-TSK-4', { signal: controller.signal }),
    ).rejects.toThrow('aborted')
  })

  it('network-firsts document records too', async () => {
    vi.mocked(fetchDocumentRecord)
      .mockResolvedValueOnce({ document_id: 'DOC-1', updated_at: '2026-07-05T00:00:00Z' })
      .mockResolvedValueOnce({ document_id: 'DOC-1', updated_at: '2026-07-06T00:00:00Z' })

    const first = await readThroughDocumentRecord<{ document_id: string; updated_at: string }>(
      'DOC-1',
    )
    expect(first.document_id).toBe('DOC-1')
    const second = await readThroughDocumentRecord<{ document_id: string; updated_at: string }>(
      'DOC-1',
    )
    expect(second.updated_at).toBe('2026-07-06T00:00:00Z')
    expect(fetchDocumentRecord).toHaveBeenCalledTimes(2)
  })
})
