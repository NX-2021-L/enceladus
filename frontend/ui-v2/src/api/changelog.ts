/**
 * Changelog reads — GET /api/v1/changelog/history (changelog_api Lambda).
 * ENC-TSK-L33 · Changelog page.
 *
 * Mirrors the shape consumed by the legacy app's
 * frontend/ui/src/api/changelog.ts (`fetchAllChangelogHistory`), trimmed to
 * what the ui-v2 Changelog page renders. The ui-v2 scaffold owns its own copy
 * of the type rather than importing the legacy app's (per the ENC-TSK-K21
 * scope constraint — see src/types/records.ts).
 */

import { queryOptions } from '@tanstack/react-query'
import { API_BASE, SessionExpiredError } from './client'

export interface ChangelogEntry {
  project_id: string
  spec_id: string
  version: string
  previous_version: string
  change_type: 'major' | 'minor' | 'patch'
  release_summary: string
  changes: string[]
  deployed_at: string
  related_record_ids: string[]
}

export interface ChangelogHistoryParams {
  limit?: number
  change_type?: 'major' | 'minor' | 'patch'
}

export class ChangelogFetchError extends Error {
  readonly status: number
  constructor(status: number, message: string) {
    super(message)
    this.name = 'ChangelogFetchError'
    this.status = status
  }
}

/** changelog_api's MAX_PROJECTS_PER_REQUEST — requests must chunk to this. */
export const MAX_PROJECTS_PER_REQUEST = 20

/** ENC-TSK-P62: split a project list into API-cap-sized request chunks. */
export function chunkProjectIds(projectIds: string[], size = MAX_PROJECTS_PER_REQUEST): string[][] {
  const chunks: string[][] = []
  for (let i = 0; i < projectIds.length; i += size) {
    chunks.push(projectIds.slice(i, i + size))
  }
  return chunks
}

async function fetchChangelogHistoryChunk(
  projectIds: string[],
  params?: ChangelogHistoryParams,
  init?: { signal?: AbortSignal },
): Promise<ChangelogEntry[]> {
  const qs = new URLSearchParams({ projects: projectIds.join(',') })
  if (params?.limit !== undefined) qs.set('limit', String(params.limit))
  if (params?.change_type) qs.set('change_type', params.change_type)

  const res = await fetch(`${API_BASE}/changelog/history?${qs.toString()}`, {
    signal: init?.signal,
    credentials: 'include',
    cache: 'no-store',
    headers: {
      accept: 'application/json',
      'x-requested-with': 'XMLHttpRequest',
    },
  })
  if (res.status === 401) throw new SessionExpiredError()
  if (!res.ok) throw new ChangelogFetchError(res.status, `Failed to fetch changelog history (${res.status})`)
  const body = (await res.json()) as { entries?: ChangelogEntry[]; count?: number }
  return body.entries ?? []
}

/**
 * Multi-project changelog history. `projectIds` empty -> skipped by callers
 * (see `changelogHistoryQueryOptions`'s `enabled` gate) since the endpoint
 * requires at least one `projects` value.
 *
 * ENC-TSK-P62 (ENC-ISS-716): changelog_api caps `projects` at 20 ids per
 * request, and the registry has grown past that — the old single request
 * 400'd for every user and /changelog never loaded. The list is now chunked
 * to the cap, chunks are fetched in parallel, and entries merge sorted by
 * deployed_at descending (the page's presentation order).
 */
export async function fetchChangelogHistory(
  projectIds: string[],
  params?: ChangelogHistoryParams,
  init?: { signal?: AbortSignal },
): Promise<ChangelogEntry[]> {
  const chunks = chunkProjectIds(projectIds)
  const results = await Promise.all(
    chunks.map((chunk) => fetchChangelogHistoryChunk(chunk, params, init)),
  )
  return results
    .flat()
    .sort((a, b) => String(b.deployed_at ?? '').localeCompare(String(a.deployed_at ?? '')))
}

export const changelogKeys = {
  history: (projectIds: string[], params?: ChangelogHistoryParams) =>
    ['changelog', 'history', [...projectIds].sort(), params] as const,
}

export const changelogHistoryQueryOptions = (
  projectIds: string[],
  params?: ChangelogHistoryParams,
) =>
  queryOptions({
    queryKey: changelogKeys.history(projectIds, params),
    queryFn: ({ signal }) => fetchChangelogHistory(projectIds, params, { signal }),
    enabled: projectIds.length > 0,
  })
