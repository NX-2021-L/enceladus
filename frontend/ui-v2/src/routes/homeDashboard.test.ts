import { describe, expect, it } from 'vitest'
import {
  DASHBOARD_RECORD_TYPES,
  facetToChartSeries,
  facetToPieData,
  pickMostRecentPerType,
  sortRecentDocuments,
  truncateDescription,
} from './homeDashboard'
import type { FeedCorpusItem } from '../sync/types'

function item(overrides: Partial<FeedCorpusItem>): FeedCorpusItem {
  return {
    record_id: 'ENC-TSK-A01',
    record_type: 'task',
    project_id: 'enceladus',
    title: 'Sample',
    updated_at: '2026-07-01T00:00:00Z',
    source: 'tracker',
    record_key: 'tracker:enceladus:ENC-TSK-A01',
    ...overrides,
  }
}

describe('truncateDescription', () => {
  it('returns empty string for empty/whitespace input', () => {
    expect(truncateDescription(undefined)).toBe('')
    expect(truncateDescription('   ')).toBe('')
  })

  it('passes short text through untouched', () => {
    expect(truncateDescription('short description', 160)).toBe('short description')
  })

  it('truncates on a word boundary and appends an ellipsis', () => {
    const text = 'a'.repeat(50) + ' ' + 'b'.repeat(50) + ' ' + 'c'.repeat(50)
    const result = truncateDescription(text, 60)
    expect(result.endsWith('…')).toBe(true)
    expect(result.length).toBeLessThanOrEqual(61)
    expect(result).not.toContain('c'.repeat(50))
  })
})

describe('pickMostRecentPerType', () => {
  it('keeps only the first (most recent) item per requested type', () => {
    const items = [
      item({ record_id: 'ENC-TSK-A02', updated_at: '2026-07-02T00:00:00Z' }),
      item({ record_id: 'ENC-TSK-A01', updated_at: '2026-07-01T00:00:00Z' }),
      item({ record_id: 'ENC-ISS-B01', record_type: 'issue', updated_at: '2026-07-03T00:00:00Z' }),
    ]
    const result = pickMostRecentPerType(items, ['task', 'issue', 'plan'])
    expect(result.task?.record_id).toBe('ENC-TSK-A02')
    expect(result.issue?.record_id).toBe('ENC-ISS-B01')
    expect(result.plan).toBeUndefined()
  })

  it('covers every dashboard record type by default', () => {
    expect(DASHBOARD_RECORD_TYPES).toHaveLength(6)
    expect(DASHBOARD_RECORD_TYPES).toContain('document')
  })
})

describe('sortRecentDocuments', () => {
  it('filters to documents only, most-recent first, capped at limit', () => {
    const items = [
      item({ record_id: 'DOC-1', record_type: 'document', source: 'document', updated_at: '2026-07-01T00:00:00Z' }),
      item({ record_id: 'ENC-TSK-A01', updated_at: '2026-07-05T00:00:00Z' }),
      item({ record_id: 'DOC-2', record_type: 'document', source: 'document', updated_at: '2026-07-04T00:00:00Z' }),
      item({ record_id: 'DOC-3', record_type: 'document', source: 'document', updated_at: '2026-07-03T00:00:00Z' }),
    ]
    const result = sortRecentDocuments(items, 2)
    expect(result.map((r) => r.record_id)).toEqual(['DOC-2', 'DOC-3'])
  })
})

describe('facetToChartSeries', () => {
  it('preserves a preferred label order and fills zero for missing labels', () => {
    const series = facetToChartSeries({ task: 12, issue: 4 }, ['task', 'issue', 'plan'])
    expect(series.labels).toEqual(['task', 'issue', 'plan'])
    expect(series.values).toEqual([12, 4, 0])
  })

  it('falls back to descending-count order with no preferred order', () => {
    const series = facetToChartSeries({ issue: 2, task: 9, plan: 5 })
    expect(series.labels).toEqual(['task', 'plan', 'issue'])
    expect(series.values).toEqual([9, 5, 2])
  })

  it('handles an undefined facet gracefully', () => {
    expect(facetToChartSeries(undefined)).toEqual({ labels: [], values: [] })
  })
})

describe('facetToPieData', () => {
  it('drops zero-count buckets and sorts largest first', () => {
    const data = facetToPieData({ open: 10, closed: 3, blocked: 0 })
    expect(data).toEqual([
      { title: 'open', value: 10 },
      { title: 'closed', value: 3 },
    ])
  })

  it('handles an undefined facet gracefully', () => {
    expect(facetToPieData(undefined)).toEqual([])
  })
})
