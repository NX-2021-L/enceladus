import { describe, expect, it } from 'vitest'
import { CorpusSearchIndex } from './searchIndex'
import type { Tier1Record } from './types'

function tier1(overrides: Partial<Tier1Record> = {}): Tier1Record {
  return {
    projectId: 'enceladus',
    recordId: 'ENC-TSK-1',
    recordType: 'task',
    title: 'Alpha task',
    status: 'open',
    source: 'tracker',
    recordKey: 'tracker:enceladus:ENC-TSK-1',
    versionSeq: '2026-07-05T00:00:00Z',
    attrs: { status: 'open' },
    ...overrides,
  }
}

describe('CorpusSearchIndex', () => {
  it('suggest filters by record id and title', () => {
    const index = new CorpusSearchIndex(10)
    index.rebuild([
      tier1({ recordId: 'ENC-TSK-1', title: 'Alpha' }),
      tier1({ recordId: 'ENC-TSK-2', title: 'Beta search' }),
    ])

    expect(index.suggest('beta').map((row) => row.recordId)).toEqual(['ENC-TSK-2'])
    expect(index.suggest('enc-tsk-1').map((row) => row.recordId)).toEqual(['ENC-TSK-1'])
  })

  it('upsert replaces an existing row and respects maxRows', () => {
    const index = new CorpusSearchIndex(2)
    index.rebuild([tier1({ recordId: 'A' }), tier1({ recordId: 'B' })])
    index.upsert(tier1({ recordId: 'A', title: 'Updated A' }))
    index.upsert(tier1({ recordId: 'C', title: 'New C' }))

    expect(index.all().map((row) => row.recordId)).toEqual(['C', 'A'])
    expect(index.all().find((row) => row.recordId === 'A')?.title).toBe('Updated A')
  })

  it('facetCounts aggregates record types', () => {
    const index = new CorpusSearchIndex(10)
    index.rebuild([
      tier1({ recordId: 'A', recordType: 'task' }),
      tier1({ recordId: 'B', recordType: 'issue' }),
      tier1({ recordId: 'C', recordType: 'task', status: 'closed' }),
    ])

    expect(index.facetCounts('recordType')).toEqual({ task: 2, issue: 1 })
    expect(index.facetCounts('status')).toEqual({ open: 2, closed: 1 })
  })
})
