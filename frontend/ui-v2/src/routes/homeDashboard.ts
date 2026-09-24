/**
 * Pure data-shaping helpers for the Home dashboard (ENC-TSK-L30 / B67 PWA2.0
 * shared home content model). Kept side-effect-free and framework-free so
 * they're unit-testable without a component-render harness (this app has no
 * @testing-library/react dependency yet — every existing *.test.ts file in
 * src/ tests extracted pure logic, so HomeRoute follows the same pattern).
 */

import type { FeedCorpusItem } from '../sync/types'
import type { RecordType } from '../types/records'

/** Order the six entry cards are rendered in (matches the AC's "one card per
 * record/doc type" + the six-primitives ordering used elsewhere, e.g.
 * routes/HomeRoute.tsx's prior ENTRY table and PLN-063 primitive registry). */
export const DASHBOARD_RECORD_TYPES: RecordType[] = [
  'task',
  'issue',
  'feature',
  'plan',
  'lesson',
  'document',
]

export const DASHBOARD_TYPE_LABEL: Record<RecordType, string> = {
  task: 'Task',
  issue: 'Issue',
  feature: 'Feature',
  plan: 'Plan',
  lesson: 'Lesson',
  document: 'Document',
}

/** Truncates a description to `maxLen` chars on a word boundary, appending an
 * ellipsis. Empty/whitespace-only input returns ''. */
export function truncateDescription(text: string | null | undefined, maxLen = 160): string {
  const trimmed = (text ?? '').trim()
  if (!trimmed) return ''
  if (trimmed.length <= maxLen) return trimmed
  const cut = trimmed.slice(0, maxLen)
  const lastSpace = cut.lastIndexOf(' ')
  const boundary = lastSpace > maxLen * 0.6 ? cut.slice(0, lastSpace) : cut
  return `${boundary.trimEnd()}…`
}

/**
 * Given the (already sort:'updated_at_desc') items of a whole-corpus feed
 * page, group by record_type and keep only the first (= most recent)
 * occurrence of each requested type. Used as a same-request fallback when a
 * per-type targeted query hasn't resolved yet, and exercised directly in
 * tests; HomeRoute prefers the per-type targeted queries for correctness
 * once the corpus outgrows a single page.
 */
export function pickMostRecentPerType(
  items: FeedCorpusItem[],
  types: RecordType[] = DASHBOARD_RECORD_TYPES,
): Partial<Record<RecordType, FeedCorpusItem>> {
  const wanted = new Set(types)
  const result: Partial<Record<RecordType, FeedCorpusItem>> = {}
  for (const item of items) {
    const type = item.record_type as RecordType
    if (!wanted.has(type) || result[type]) continue
    result[type] = item
  }
  return result
}

/** Most-recent-first documents, capped at `limit`. Assumes `items` is already
 * sorted 'updated_at_desc' (the default corpus sort) — re-sorts defensively
 * so callers don't have to trust request params. */
export function sortRecentDocuments(items: FeedCorpusItem[], limit = 6): FeedCorpusItem[] {
  return [...items]
    .filter((item) => item.record_type === 'document')
    .sort((a, b) => (b.updated_at ?? '').localeCompare(a.updated_at ?? ''))
    .slice(0, limit)
}

export interface ChartSeries {
  labels: string[]
  values: number[]
}

/** Turns a corpus `facets.record_type` (or `.status`) map into ordered
 * label/value arrays for BarChart, filling zero for any requested label
 * absent from the facet (e.g. a type with no records yet). Sorted by
 * `preferredOrder` when given, else by descending count. */
export function facetToChartSeries(
  facet: Record<string, number> | undefined,
  preferredOrder?: string[],
): ChartSeries {
  const source = facet ?? {}
  const labels = preferredOrder ?? Object.keys(source).sort((a, b) => (source[b] ?? 0) - (source[a] ?? 0))
  return {
    labels,
    values: labels.map((label) => source[label] ?? 0),
  }
}

export interface PieDatum {
  title: string
  value: number
}

/** Turns a facet map into PieChart `data` entries, dropping zero-count
 * buckets (an empty slice is visual noise, not information) and sorting
 * largest-first so the legend reads in priority order. */
export function facetToPieData(facet: Record<string, number> | undefined): PieDatum[] {
  const source = facet ?? {}
  return Object.entries(source)
    .filter(([, value]) => value > 0)
    .sort((a, b) => b[1] - a[1])
    .map(([title, value]) => ({ title, value }))
}
