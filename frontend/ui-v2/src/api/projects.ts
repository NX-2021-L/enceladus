/**
 * Project registry reads — GET /api/v1/projects (project_service).
 * Used to map record-id prefixes (e.g. ENC) to owning project slugs.
 */

import { API_BASE, SessionExpiredError } from './client'

export interface ProjectSummary {
  project_id: string
  prefix: string
  name?: string
  status?: string
}

export interface ProjectsListResponse {
  success: boolean
  projects: ProjectSummary[]
  count: number
}

export class ProjectsFetchError extends Error {
  readonly status: number
  constructor(status: number, message: string) {
    super(message)
    this.name = 'ProjectsFetchError'
    this.status = status
  }
}

export async function fetchProjectsList(init?: { signal?: AbortSignal }): Promise<ProjectSummary[]> {
  const res = await fetch(`${API_BASE}/projects`, {
    signal: init?.signal,
    credentials: 'include',
    cache: 'no-store',
    headers: {
      accept: 'application/json',
      'x-requested-with': 'XMLHttpRequest',
    },
  })
  if (res.status === 401) throw new SessionExpiredError()
  if (!res.ok) throw new ProjectsFetchError(res.status, `Failed to list projects (${res.status})`)
  const body = (await res.json()) as ProjectsListResponse
  return body.projects ?? []
}
