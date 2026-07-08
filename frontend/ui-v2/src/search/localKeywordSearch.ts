import type { LocalSearchRecord, SearchResultHit } from '../types/search'

/**
 * Tier-0 local keyword search — synchronous, bounded, intended to complete
 * within the <100ms autosuggest SLO (FTR-127). No network I/O.
 */
function toHit(row: LocalSearchRecord): SearchResultHit {
  return {
    recordId: row.recordId,
    recordType: row.recordType,
    projectId: row.projectId,
    title: row.title,
    status: row.status,
    priority: row.priority,
    checkoutState: row.checkoutState,
    tier: 'local',
  }
}

export function searchLocalKeyword(
  corpus: LocalSearchRecord[],
  query: string,
  limit = 20,
): SearchResultHit[] {
  const q = query.trim().toLowerCase()
  if (!q) {
    // ENC-FTR-130 Band-B: a blank query means the caller is browsing/
    // filtering rather than typing a search (e.g. Home's counts-strip deep
    // links, which navigate straight to a property-filtered /feed?f=... URL
    // with no `q`). Property-filter narrowing (applyPropertyFilter) only has
    // something to narrow if the local tier returns the full corpus here --
    // returning [] silently zeroed out every filter-only Feed deep link
    // regardless of whether the filter itself was correct.
    return corpus.map(toHit)
  }

  const hits: SearchResultHit[] = []
  for (const row of corpus) {
    const idMatch = row.recordId.toLowerCase().includes(q)
    const titleMatch = row.title.toLowerCase().includes(q)
    if (!idMatch && !titleMatch) continue
    hits.push(toHit(row))
    if (hits.length >= limit) break
  }
  return hits
}
