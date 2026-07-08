import type { LocalSearchRecord } from '../types/search'
import type { Tier1Record } from './types'

/** Device-budgeted in-memory search index over the cached Tier-1 slice. */
export class CorpusSearchIndex {
  private rows: LocalSearchRecord[] = []
  private maxRows: number

  constructor(maxRows = 2_000) {
    this.maxRows = maxRows
  }

  rebuild(records: Tier1Record[]): void {
    const mapped = records.map(tier1ToLocalSearchRecord)
    this.rows = mapped.slice(0, this.maxRows)
  }

  upsert(record: Tier1Record): void {
    const next = tier1ToLocalSearchRecord(record)
    this.rows = [next, ...this.rows.filter((row) => row.recordId !== next.recordId)].slice(
      0,
      this.maxRows,
    )
  }

  remove(recordId: string): void {
    this.rows = this.rows.filter((row) => row.recordId !== recordId)
  }

  all(): LocalSearchRecord[] {
    return this.rows
  }

  suggest(query: string, limit = 12): LocalSearchRecord[] {
    const needle = query.trim().toLowerCase()
    const pool = needle
      ? this.rows.filter(
          (row) =>
            row.recordId.toLowerCase().includes(needle) ||
            row.title.toLowerCase().includes(needle),
        )
      : this.rows
    return pool.slice(0, limit)
  }

  facetCounts(field: 'recordType' | 'status' | 'projectId'): Record<string, number> {
    const counts: Record<string, number> = {}
    for (const row of this.rows) {
      const value =
        field === 'recordType'
          ? row.recordType
          : field === 'status'
            ? row.status ?? 'unknown'
            : row.projectId
      counts[value] = (counts[value] ?? 0) + 1
    }
    return counts
  }
}

export function tier1ToLocalSearchRecord(record: Tier1Record): LocalSearchRecord {
  return {
    recordId: record.recordId,
    recordType: record.recordType,
    projectId: record.projectId,
    title: record.title,
    status: record.status,
    // ENC-FTR-130 Band-B: Tier1Record already carries priority (and a raw
    // attrs bag with checkout_state) -- this mapping was dropping both on
    // the floor before they ever reached the search/filter layer.
    priority: record.priority,
    checkoutState:
      typeof record.attrs?.checkout_state === 'string' ? record.attrs.checkout_state : undefined,
    // ENC-TSK-M35 (PAR-01): Tier1Record already carries updatedAt -- restore
    // it to the search/filter layer alongside priority/checkout_state.
    updatedAt: record.updatedAt ?? undefined,
  }
}
