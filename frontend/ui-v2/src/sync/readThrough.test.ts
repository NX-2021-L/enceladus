import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchDocumentRecord, fetchTrackerRecord } from '../api/client'
import { resetCacheEngineForTests } from './cacheEngine'
import { readThroughDocumentRecord, readThroughTrackerRecord } from './readThrough'

vi.mock('../api/client', () => ({
  fetchTrackerRecord: vi.fn(),
  fetchDocumentRecord: vi.fn(),
}))

describe('readThrough fetchers', () => {
  beforeEach(() => {
    resetCacheEngineForTests()
    vi.mocked(fetchTrackerRecord).mockReset()
    vi.mocked(fetchDocumentRecord).mockReset()
  })

  it('returns cached tier2 without network', async () => {
    vi.mocked(fetchTrackerRecord).mockResolvedValue({ record_id: 'ENC-TSK-1', updated_at: '2' })
    const first = await readThroughTrackerRecord('task', 'enceladus', 'ENC-TSK-1')
    const second = await readThroughTrackerRecord('task', 'enceladus', 'ENC-TSK-1')

    expect(first).toEqual({ record_id: 'ENC-TSK-1', updated_at: '2' })
    expect(second).toEqual(first)
    expect(fetchTrackerRecord).toHaveBeenCalledTimes(1)
  })

  it('read-throughs document records into tier2', async () => {
    vi.mocked(fetchDocumentRecord).mockResolvedValue({
      document_id: 'DOC-1',
      updated_at: '2026-07-05T00:00:00Z',
    })

    const body = await readThroughDocumentRecord<{ document_id: string }>('DOC-1')
    expect(body.document_id).toBe('DOC-1')
    expect(fetchDocumentRecord).toHaveBeenCalledTimes(1)

    await readThroughDocumentRecord('DOC-1')
    expect(fetchDocumentRecord).toHaveBeenCalledTimes(1)
  })
})
