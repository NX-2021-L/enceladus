import type { RecordType } from '../types/records'

/** Typed route paths — tracker primitives include the owning project slug. */
export const TRACKER_ROUTE_PATH: Record<
  Exclude<RecordType, 'document'>,
  string
> = {
  task: '/$project/task/$id',
  issue: '/$project/issue/$id',
  feature: '/$project/feature/$id',
  plan: '/$project/plan/$id',
  lesson: '/$project/lesson/$id',
}

export const DOCUMENT_ROUTE_PATH = '/document/$id'

/** @deprecated Use trackerRoutePath / documentRoutePath — kept for gradual migration. */
export const RECORD_ROUTE_PATH: Record<RecordType, string> = {
  ...TRACKER_ROUTE_PATH,
  document: DOCUMENT_ROUTE_PATH,
}

export function trackerRoutePath(type: Exclude<RecordType, 'document'>): string {
  return TRACKER_ROUTE_PATH[type]
}

/** Builds a concrete href, e.g. ('enceladus','task','ENC-TSK-K21') -> '/enceladus/task/ENC-TSK-K21'. */
export function recordHref(
  projectId: string,
  type: Exclude<RecordType, 'document'>,
  id: string,
): string {
  return `/${encodeURIComponent(projectId)}/${type}/${encodeURIComponent(id)}`
}

export function documentHref(id: string): string {
  return `/document/${encodeURIComponent(id)}`
}

/** Builds a concrete href for any record type. */
export function recordHrefForType(
  projectId: string | null,
  type: RecordType,
  id: string,
): string {
  if (type === 'document') return documentHref(id)
  if (!projectId) throw new Error(`projectId required for ${type} link`)
  return recordHref(projectId, type, id)
}
