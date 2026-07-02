import type { RecordType } from '../types/records'

/** Maps a record type to its concrete typed route path. Keeps the six routes
 *  as the single navigation surface (no dynamic `/$type/$id` catch-all). */
export const RECORD_ROUTE_PATH: Record<RecordType, string> = {
  task: '/task/$id',
  issue: '/issue/$id',
  feature: '/feature/$id',
  plan: '/plan/$id',
  lesson: '/lesson/$id',
  document: '/document/$id',
}

/** Builds a concrete href for a record, e.g. ('task','ENC-TSK-K21') -> '/task/ENC-TSK-K21'. */
export function recordHref(type: RecordType, id: string): string {
  return `/${type}/${encodeURIComponent(id)}`
}
