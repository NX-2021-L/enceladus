import { describe, expect, it } from 'vitest'
import { PLAN_PAGE_SIZE, nextPlanCount, selectPlans } from './selectPlans'
import type { LensRow } from './types'

const plan = (item_id: string, created_at: string | null | undefined, project_id = 'enceladus', extra: Partial<LensRow> = {}): LensRow => ({
  item_id,
  record_type: 'plan',
  project_id,
  created_at,
  ...extra,
})

const ids = (rows: readonly LensRow[]) => rows.map((r) => r.item_id)

describe('selectPlans', () => {
  it('returns plans ordered by created_at descending (R5)', () => {
    const corpus = [plan('A', '2026-11-01T00:00:00Z'), plan('C', '2026-11-18T00:00:00Z'), plan('B', '2026-11-10T00:00:00Z')]
    expect(ids(selectPlans(corpus).plans)).toEqual(['C', 'B', 'A'])
  })

  it('compares instants, not strings: offsets and fractional seconds order correctly', () => {
    const corpus = [
      plan('EARLIER', '2026-11-18T10:00:00-08:00'), // 18:00Z
      plan('LATER', '2026-11-18T17:00:00-08:00'), // 01:00Z next day
      plan('MID', '2026-11-18T20:00:00.500Z'),
    ]
    expect(ids(selectPlans(corpus).plans)).toEqual(['LATER', 'MID', 'EARLIER'])
  })

  it('keeps only plan rows', () => {
    const corpus: LensRow[] = [
      plan('P', '2026-11-01T00:00:00Z'),
      { item_id: 'T', record_type: 'task', created_at: '2026-11-19T00:00:00Z', project_id: 'enceladus' },
      { item_id: 'I', record_type: 'issue', created_at: '2026-11-19T00:00:00Z', project_id: 'enceladus' },
      { item_id: 'P2', record_type: 'PLAN', created_at: '2026-11-02T00:00:00Z', project_id: 'enceladus' },
    ]
    expect(ids(selectPlans(corpus).plans)).toEqual(['P2', 'P'])
  })

  it('filters by project, and null, undefined and empty mean All projects (D-8)', () => {
    const corpus = [plan('E1', '2026-11-03T00:00:00Z', 'enceladus'), plan('F1', '2026-11-04T00:00:00Z', 'fin'), plan('E2', '2026-11-05T00:00:00Z', 'enceladus')]
    expect(ids(selectPlans(corpus, { project: 'enceladus' }).plans)).toEqual(['E2', 'E1'])
    expect(ids(selectPlans(corpus, { project: 'fin' }).plans)).toEqual(['F1'])
    for (const project of [null, undefined, '']) expect(ids(selectPlans(corpus, { project }).plans)).toEqual(['E2', 'F1', 'E1'])
    expect(selectPlans(corpus, { project: 'nobody' })).toEqual({ plans: [], total: 0, remaining: 0, hasMore: false })
  })

  it('shows the newest 20 first and reports what remains (D-9)', () => {
    const corpus = Array.from({ length: 47 }, (_, i) => plan(`P${String(i).padStart(2, '0')}`, new Date(Date.UTC(2026, 0, 1 + i)).toISOString()))
    const first = selectPlans(corpus)
    expect(PLAN_PAGE_SIZE).toBe(20)
    expect(first.plans).toHaveLength(20)
    expect(first.plans[0]?.item_id).toBe('P46')
    expect(first.plans.at(-1)?.item_id).toBe('P27')
    expect(first).toMatchObject({ total: 47, remaining: 27, hasMore: true })
  })

  it('older pages extend the same ordering without gaps or repeats', () => {
    const corpus = Array.from({ length: 47 }, (_, i) => plan(`P${String(i).padStart(2, '0')}`, new Date(Date.UTC(2026, 0, 1 + i)).toISOString()))
    let count: number | undefined
    let previous: string[] = []
    for (const expected of [20, 40, 47]) {
      const r = selectPlans(corpus, { count })
      expect(r.plans).toHaveLength(expected)
      expect(ids(r.plans).slice(0, previous.length)).toEqual(previous)
      previous = ids(r.plans)
      count = nextPlanCount(count)
    }
    expect(selectPlans(corpus, { count: 60 })).toMatchObject({ remaining: 0, hasMore: false })
  })

  it('a plan with no usable created_at sorts after every dated plan, with a total order', () => {
    const corpus = [plan('NODATE-1', undefined), plan('BAD', 'not a date'), plan('DATED', '2020-01-01T00:00:00Z'), plan('NODATE-2', null)]
    const got = ids(selectPlans(corpus).plans)
    expect(got[0]).toBe('DATED')
    expect(got.slice(1)).toEqual(['NODATE-2', 'NODATE-1', 'BAD'].sort((a, b) => b.localeCompare(a, 'en', { numeric: true })))
  })

  it('does not fall back to updated_at: R5 is creation order', () => {
    const corpus = [plan('OLD-BUT-TOUCHED', '2026-01-01T00:00:00Z', 'enceladus', { updated_at: '2026-11-19T00:00:00Z' } as Partial<LensRow>), plan('NEW', '2026-11-01T00:00:00Z')]
    expect(ids(selectPlans(corpus).plans)).toEqual(['NEW', 'OLD-BUT-TOUCHED'])
  })

  it('breaks equal created_at on item_id descending, numeric-aware, so the page is deterministic', () => {
    const at = '2026-11-01T00:00:00Z'
    const corpus = [plan('ENC-PLN-9', at), plan('ENC-PLN-100', at), plan('ENC-PLN-10', at)]
    expect(ids(selectPlans(corpus).plans)).toEqual(['ENC-PLN-100', 'ENC-PLN-10', 'ENC-PLN-9'])
  })

  it('gives the same page whatever the input order', () => {
    const corpus = [plan('A', '2026-11-01T00:00:00Z'), plan('B', '2026-11-02T00:00:00Z'), plan('C', undefined), plan('D', '2026-11-02T00:00:00Z')]
    const forward = ids(selectPlans(corpus).plans)
    expect(ids(selectPlans([...corpus].reverse()).plans)).toEqual(forward)
  })

  it('does not mutate the corpus it is given', () => {
    const corpus = [plan('A', '2026-11-01T00:00:00Z'), plan('B', '2026-11-02T00:00:00Z')]
    const before = ids(corpus)
    selectPlans(corpus)
    expect(ids(corpus)).toEqual(before)
  })

  it('a count of zero or less shows nothing but still counts', () => {
    const corpus = [plan('A', '2026-11-01T00:00:00Z')]
    expect(selectPlans(corpus, { count: 0 })).toMatchObject({ plans: [], total: 1, remaining: 1, hasMore: true })
    expect(selectPlans(corpus, { count: -5 }).plans).toEqual([])
  })

  it('an empty corpus selects nothing', () => {
    expect(selectPlans([])).toEqual({ plans: [], total: 0, remaining: 0, hasMore: false })
  })
})
