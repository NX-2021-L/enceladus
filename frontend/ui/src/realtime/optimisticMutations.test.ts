import { describe, it, expect, beforeEach } from 'vitest'
import { QueryClient } from '@tanstack/react-query'
import {
  createOptimisticHandlers,
  resolveConflict,
  ifMatchHeaders,
  type RecordLike,
  type StatusMutationVars,
} from './optimisticMutations'

const detailKey = (type: string, id: string) => ['record', type, id] as const
const planKeyPrefix = ['plan'] as const
const feedKey = ['feed', 'live'] as const

describe('createOptimisticHandlers (AC-5, AC-6, AC-7)', () => {
  let qc: QueryClient
  beforeEach(() => {
    qc = new QueryClient()
    qc.setQueryData(detailKey('task', 'T1'), { recordId: 'T1', status: 'open' })
    qc.setQueryData(['plan', 'P1'], {
      recordId: 'P1',
      tasks: [
        { recordId: 'T1', status: 'open' },
        { recordId: 'T2', status: 'open' },
      ],
    })
    qc.setQueryData(feedKey, { events: [] })
  })

  const vars: StatusMutationVars = {
    recordId: 'T1',
    recordType: 'task',
    patch: { status: 'closed' },
    version: 7,
  }

  it('applies the optimistic update to the detail query (step 3a)', async () => {
    const h = createOptimisticHandlers({ queryClient: qc, detailKey, planKeyPrefix, feedKey })
    await h.onMutate(vars)
    expect(qc.getQueryData<RecordLike>(detailKey('task', 'T1'))?.status).toBe('closed')
  })

  it('propagates across all cached plan pages in one predicate call (AC-6)', async () => {
    const h = createOptimisticHandlers({ queryClient: qc, detailKey, planKeyPrefix, feedKey })
    await h.onMutate(vars)
    const plan = qc.getQueryData<RecordLike>(['plan', 'P1'])
    expect(plan?.tasks?.find((t) => t.recordId === 'T1')?.status).toBe('closed')
    expect(plan?.tasks?.find((t) => t.recordId === 'T2')?.status).toBe('open')
  })

  it('prepends an optimistic pending event to the feed (AC-9 setup)', async () => {
    const registered: string[] = []
    const h = createOptimisticHandlers({
      queryClient: qc,
      detailKey,
      planKeyPrefix,
      feedKey,
      makeEventId: () => 'evt-opt-1',
      registerOptimistic: (id) => registered.push(id),
    })
    await h.onMutate(vars)
    const feed = qc.getQueryData<{ events: Array<{ pending?: boolean; action: string }> }>(feedKey)
    expect(feed?.events[0].pending).toBe(true)
    expect(feed?.events[0].action).toBe('closed')
    expect(registered).toContain('evt-opt-1')
  })

  it('rolls back every snapshot atomically on error (AC-7)', async () => {
    const h = createOptimisticHandlers({ queryClient: qc, detailKey, planKeyPrefix, feedKey })
    const ctx = await h.onMutate(vars)
    // sanity: optimistic applied
    expect(qc.getQueryData<RecordLike>(detailKey('task', 'T1'))?.status).toBe('closed')
    h.onError(new Error('500'), vars, ctx)
    expect(qc.getQueryData<RecordLike>(detailKey('task', 'T1'))?.status).toBe('open')
    const plan = qc.getQueryData<RecordLike>(['plan', 'P1'])
    expect(plan?.tasks?.find((t) => t.recordId === 'T1')?.status).toBe('open')
  })
})

describe('conflict resolution (AC-19)', () => {
  it('builds an If-Match header from the version', () => {
    expect(ifMatchHeaders(7)).toEqual({ 'If-Match': '7' })
    expect(ifMatchHeaders(undefined)).toEqual({})
  })

  it('resolves governance-critical fields server-wins', () => {
    const merges = resolveConflict(
      { status: 'closed', priority: 'P1' },
      { recordId: 'T1', status: 'pr', priority: 'P0' },
    )
    expect(merges.every((m) => m.resolution === 'server-wins')).toBe(true)
    expect(merges.map((m) => m.field).sort()).toEqual(['priority', 'status'])
  })

  it('surfaces a field-level merge UI for independent fields', () => {
    const merges = resolveConflict(
      { description: 'local text' },
      { recordId: 'T1', description: 'server text' },
    )
    expect(merges).toHaveLength(1)
    expect(merges[0].resolution).toBe('merge-ui')
  })

  it('ignores identical values', () => {
    const merges = resolveConflict(
      { status: 'closed', title: 'same' },
      { recordId: 'T1', status: 'closed', title: 'same' },
    )
    expect(merges).toHaveLength(0)
  })
})
