import type { FeedSort } from './feedSearchParams'
import type { SearchResultHit } from '../types/search'

export function sortSearchHits(hits: SearchResultHit[], sort: FeedSort): SearchResultHit[] {
  if (sort === 'tier') return hits

  const copy = [...hits]
  switch (sort) {
    case 'id':
      copy.sort((a, b) => a.recordId.localeCompare(b.recordId))
      break
    case 'title':
      copy.sort((a, b) => a.title.localeCompare(b.title))
      break
    case 'status':
      copy.sort((a, b) => (a.status ?? '').localeCompare(b.status ?? ''))
      break
    case 'updated':
      // ENC-TSK-N56 (ENC-TSK-N45 UAT follow-up): most-recently-updated first.
      // updatedAt is an ISO-8601 string, so a reverse lexicographic compare is
      // a correct chronological descending sort. Records with no timestamp sort
      // last so they never masquerade as the newest.
      copy.sort((a, b) => {
        const av = a.updatedAt ?? ''
        const bv = b.updatedAt ?? ''
        if (av === bv) return 0
        if (!av) return 1
        if (!bv) return -1
        return bv.localeCompare(av)
      })
      break
    default:
      break
  }
  return copy
}
