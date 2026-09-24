import { describe, expect, it } from 'vitest'
import { DEFAULT_DOCS_SORT, SORT_OPTIONS } from './DocsRoute'
import { sortSearchHits } from '../search/sortSearchHits'
import type { SearchResultHit } from '../types/search'

/**
 * ENC-TSK-N57 (ENC-TSK-N45/N56 UAT follow-up): /docs must default to
 * most-recently-updated first. These tests pin the *default resolution* — that
 * the initial sort is 'updated' and that resolving it through the shared
 * sortSearchHits machinery yields newest-first. The ordering primitive itself
 * (ISO desc, missing-timestamps-last) is covered by sortSearchHits.test.ts.
 */
describe('DocsRoute default sort', () => {
  it('defaults to Last Updated (updated), newest-first', () => {
    expect(DEFAULT_DOCS_SORT).toBe('updated')
  })

  it('exposes Last Updated as the first, default-labelled sort option', () => {
    const first = SORT_OPTIONS[0]!
    expect(first.value).toBe(DEFAULT_DOCS_SORT)
    expect(first.label).toMatch(/default/i)
    // The old 'Relevance (default)' label must no longer claim to be default.
    const tier = SORT_OPTIONS.find((o) => o.value === 'tier')!
    expect(tier.label).toBe('Relevance')
  })

  it('resolves the default sort to newest-updated-first ordering', () => {
    const hits: SearchResultHit[] = [
      { recordId: 'DOC-OLD', recordType: 'document', projectId: 'enceladus', title: 'Old', updatedAt: '2026-07-01T00:00:00Z' },
      { recordId: 'DOC-NEW', recordType: 'document', projectId: 'enceladus', title: 'New', updatedAt: '2026-07-12T00:00:00Z' },
      { recordId: 'DOC-NONE', recordType: 'document', projectId: 'enceladus', title: 'None' },
      { recordId: 'DOC-MID', recordType: 'document', projectId: 'enceladus', title: 'Mid', updatedAt: '2026-07-06T00:00:00Z' },
    ]
    expect(sortSearchHits(hits, DEFAULT_DOCS_SORT).map((h) => h.recordId)).toEqual([
      'DOC-NEW',
      'DOC-MID',
      'DOC-OLD',
      'DOC-NONE',
    ])
  })
})
