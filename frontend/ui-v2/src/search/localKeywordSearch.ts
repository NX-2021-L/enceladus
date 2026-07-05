import type { LocalSearchRecord, SearchResultHit } from '../types/search'

/**
 * Tier-0 local keyword search — synchronous, bounded, intended to complete
 * within the <100ms autosuggest SLO (FTR-127). No network I/O.
 */
export function searchLocalKeyword(
  corpus: LocalSearchRecord[],
  query: string,
  limit = 20,
): SearchResultHit[] {
  const q = query.trim().toLowerCase()
  if (!q) return []

  const hits: SearchResultHit[] = []
  for (const row of corpus) {
    const idMatch = row.recordId.toLowerCase().includes(q)
    const titleMatch = row.title.toLowerCase().includes(q)
    if (!idMatch && !titleMatch) continue
    hits.push({
      recordId: row.recordId,
      recordType: row.recordType,
      projectId: row.projectId,
      title: row.title,
      status: row.status,
      tier: 'local',
    })
    if (hits.length >= limit) break
  }
  return hits
}
