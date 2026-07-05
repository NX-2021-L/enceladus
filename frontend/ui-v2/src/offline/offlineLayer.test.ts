import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  clearMutationQueueForTests,
  enqueueMutation,
  getPendingMutationCount,
} from './mutationQueue'
import {
  GOVERNANCE_CRITICAL_FIELDS,
  mergeConflictFields,
  readSyncVersion,
  RevisionConflictError,
} from '../api/mutations'

describe('mutationQueue', () => {
  afterEach(async () => {
    await clearMutationQueueForTests()
  })

  it('tracks pending offline mutations', async () => {
    expect(await getPendingMutationCount()).toBe(0)
    await enqueueMutation({
      url: '/api/v1/tracker/enceladus/task/ENC-TSK-1',
      method: 'PATCH',
      body: { field: 'status', value: 'closed' },
      headers: { 'If-Match': '3' },
    })
    expect(await getPendingMutationCount()).toBe(1)
  })
})

describe('If-Match / 409 merge policy (K25 AC-3)', () => {
  it('reads sync_version from tracker records', () => {
    expect(readSyncVersion({ sync_version: 7 })).toBe(7)
    expect(readSyncVersion({ sync_version: '4' })).toBe(4)
  })

  it('server-wins on governance-critical fields', () => {
    for (const field of GOVERNANCE_CRITICAL_FIELDS) {
      expect(mergeConflictFields(field, 'open', { [field]: 'closed' })).toBe('server-wins')
    }
  })

  it('side-by-side on independent fields when values differ', () => {
    expect(mergeConflictFields('title', 'A', { title: 'B' })).toBe('side-by-side')
  })

  it('RevisionConflictError carries structured details', () => {
    const err = new RevisionConflictError('conflict', {
      code: 'REVISION_CONFLICT',
      record_id: 'ENC-TSK-1',
      expected_revision: '2',
      current_revision: 3,
    })
    expect(err.status).toBe(409)
    expect(err.details.current_revision).toBe(3)
  })
})

describe('offline enqueue when navigator offline', () => {
  afterEach(async () => {
    vi.unstubAllGlobals()
    await clearMutationQueueForTests()
  })

  it('queues PATCH when offline', async () => {
    vi.stubGlobal('navigator', { onLine: false })
    const { patchTrackerRecord } = await import('../api/mutations')
    const result = await patchTrackerRecord('enceladus', 'task', 'ENC-TSK-9', {
      action: 'note',
      note: 'offline note',
    })
    expect(result.success).toBe(true)
    expect(await getPendingMutationCount()).toBe(1)
  })
})
