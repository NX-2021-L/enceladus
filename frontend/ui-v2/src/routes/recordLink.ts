import type { RecordType } from '../types/records'
import type { ProjectSummary } from '../api/projects'
import {
  inferRecordNavigation,
  resolveProjectFromRecordId,
} from '../api/projectRegistry'

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

/** Sessions and agent types are not project-scoped (globally unique ids). */
export const SESSION_ROUTE_PATH = '/session/$id'
export const AGENT_ROUTE_PATH = '/agent/$agentTypeId'

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

/** A router-navigate target: `navigate({ to, params })`. */
export interface RecordTarget {
  to: string
  params: Record<string, string>
}

const TRACKER_TYPES: ReadonlySet<string> = new Set([
  'task',
  'issue',
  'feature',
  'plan',
  'lesson',
])

/**
 * ENC-TSK-P58 — the single id→route resolver (ENC-ISS-712/713 root cause).
 *
 * Maps ANY governed record id (task/issue/feature/plan/lesson/document/
 * session/agent-type, any project prefix) to its typed route target, or null
 * when the id cannot be resolved to a routable record. Callers must treat
 * null as "do not navigate" — guessing a route is exactly the defect this
 * replaces.
 *
 * `recordTypeHint` wins over ID-shape inference when provided (e.g. graph
 * node data carrying record_type once UAT-W4 lands); tracker hints still
 * need the project registry to resolve the owning project slug.
 */
export function resolveRecordTarget(
  rawId: string,
  projects: ProjectSummary[],
  recordTypeHint?: string,
): RecordTarget | null {
  const id = rawId.trim()
  if (!id) return null
  const upper = id.toUpperCase()
  const mid = upper.split('-')[1]

  const hint = recordTypeHint?.toLowerCase()
  if (hint === 'session' || (!hint && mid === 'SES')) {
    return { to: SESSION_ROUTE_PATH, params: { id } }
  }
  if (hint === 'agent' || hint === 'agent_type' || (!hint && mid === 'AGT')) {
    return { to: AGENT_ROUTE_PATH, params: { agentTypeId: id } }
  }
  if (hint === 'document') {
    return { to: DOCUMENT_ROUTE_PATH, params: { id } }
  }
  if (hint && TRACKER_TYPES.has(hint)) {
    const projectId = resolveProjectFromRecordId(upper, projects)
    if (!projectId) return null
    return {
      to: trackerRoutePath(hint as Exclude<RecordType, 'document'>),
      params: { project: projectId, id },
    }
  }

  const nav = inferRecordNavigation(id, projects)
  if (!nav) return null
  if (nav.type === 'document') {
    return { to: DOCUMENT_ROUTE_PATH, params: { id: nav.id } }
  }
  if (!nav.projectId) return null
  return {
    to: trackerRoutePath(nav.type),
    params: { project: nav.projectId, id: nav.id },
  }
}
