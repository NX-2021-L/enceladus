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
    default:
      break
  }
  return copy
}
