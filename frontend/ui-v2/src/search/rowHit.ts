import type { IndexRow } from '@io-kit/search'
import type { RecordType } from '../types/records'
import type { SearchResultHit } from '../types/search'

const f = (row: IndexRow, key: string): string | undefined => {
  const v = row.fields[key]
  return typeof v === 'string' && v ? v : undefined
}

/** Corpus row -> the hit the existing record cards and reading pane render. */
export function rowToHit(row: IndexRow, hybrid = false): SearchResultHit {
  const status = f(row, 'status')
  const priority = f(row, 'priority')
  const checkoutState = f(row, 'checkout_state')
  return {
    recordId: row.id,
    recordType: row.type as RecordType,
    projectId: f(row, 'project_id') ?? (row.type === 'document' ? 'global' : 'enceladus'),
    title: row.title,
    ...(status ? { status } : {}),
    ...(priority ? { priority } : {}),
    ...(checkoutState ? { checkoutState } : {}),
    ...(row.updatedAt ? { updatedAt: row.updatedAt } : {}),
    tier: hybrid ? 'hybrid' : 'local',
  }
}

/** Evidence chips render against these states; graph is unavailable on enceladus today (kit degraded rules). */
export const ENCELADUS_SIGNAL_AVAILABILITY = { keyword: 'available', vector: 'available', graph: 'unavailable' } as const
