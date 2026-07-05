/**
 * Project slug registry — resolves record-id prefixes to tracker project_id
 * values using GET /api/v1/projects (ENC-ISS-487 / ENC-TSK-L17).
 */

import { queryOptions } from '@tanstack/react-query'
import { fetchProjectsList, type ProjectSummary } from './projects'
import type { RecordType } from '../types/records'

export const projectRegistryKeys = {
  all: ['projects', 'registry'] as const,
}

export const projectRegistryQueryOptions = queryOptions({
  queryKey: projectRegistryKeys.all,
  queryFn: ({ signal }) => fetchProjectsList({ signal }),
  staleTime: 10 * 60 * 1000,
})

/** Map the first segment of a record id (e.g. ENC) to a project slug. */
export function resolveProjectFromRecordId(
  recordId: string,
  projects: ProjectSummary[],
): string | null {
  const prefix = recordId.split('-')[0]
  if (!prefix) return null
  const match = projects.find((p) => p.prefix === prefix)
  return match?.project_id ?? null
}

const PREFIX_TO_TYPE: Record<string, RecordType> = {
  TSK: 'task',
  ISS: 'issue',
  FTR: 'feature',
  PLN: 'plan',
  LSN: 'lesson',
}

/** Infer record type and owning project from a raw id string (CommandPalette). */
export function inferRecordNavigation(
  raw: string,
  projects: ProjectSummary[],
): { type: RecordType; id: string; projectId: string | null } | null {
  const id = raw.trim().toUpperCase()
  if (!id) return null

  if (id.startsWith('DOC-')) {
    return { type: 'document', id, projectId: null }
  }

  const mid = id.split('-')[1]
  const type = mid ? PREFIX_TO_TYPE[mid] : undefined
  if (!type) return null

  return {
    type,
    id,
    projectId: resolveProjectFromRecordId(id, projects),
  }
}
