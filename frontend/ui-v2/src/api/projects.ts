/**
 * Project registry reads — GET /api/v1/projects (project_service).
 * Used to map record-id prefixes (e.g. ENC) to owning project slugs, and to
 * back the Projects page (Cards) + create-project flow (ENC-TSK-L31).
 */

import { API_BASE, SessionExpiredError } from './client'

export interface ProjectSummary {
  project_id: string
  prefix: string
  name?: string
  status?: string
  /** Free-text project description (project_service GET /projects). */
  summary?: string
  parent?: string
  repo?: string
  deploy_policy?: string
  created_at?: string
  updated_at?: string
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

/**
 * Create-project flow (ENC-TSK-L31). Targets the same project_service
 * POST /api/v1/projects route already implemented server-side
 * (backend/lambda/project_service/lambda_function.py `_handle_create`) —
 * no backend changes were required for this task.
 */
export interface CreateProjectRequest {
  name: string
  prefix: string
  summary: string
  status: string
  parent?: string
  repo?: string
}

export interface CreateProjectResponse {
  success: boolean
  project: ProjectSummary & { created_by?: string }
  initialization: Record<string, string>
}

export class ProjectCreateError extends Error {
  readonly status: number
  readonly details?: Record<string, unknown>
  constructor(status: number, message: string, details?: Record<string, unknown>) {
    super(message)
    this.name = 'ProjectCreateError'
    this.status = status
    this.details = details
  }
}

export async function createProject(data: CreateProjectRequest): Promise<CreateProjectResponse> {
  const res = await fetch(`${API_BASE}/projects`, {
    method: 'POST',
    credentials: 'include',
    cache: 'no-store',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json',
      'x-requested-with': 'XMLHttpRequest',
    },
    body: JSON.stringify(data),
  })
  const body = (await res.json().catch(() => ({}))) as Record<string, unknown>
  if (res.status === 401) throw new SessionExpiredError()
  if (!res.ok) {
    const message = (body.error as string) || (body.message as string) || `Request failed (${res.status})`
    throw new ProjectCreateError(res.status, message, body)
  }
  return body as unknown as CreateProjectResponse
}

const PROJECT_ID_PATTERN = /^[a-z][a-z0-9_-]{0,49}$/
const PREFIX_PATTERN = /^[A-Z]{3}$/

export const PROJECT_STATUS_OPTIONS = [
  { value: 'planning', label: 'Planning' },
  { value: 'development', label: 'Development' },
  { value: 'active_production', label: 'Active Production' },
] as const

export interface FieldValidation {
  valid: boolean
  error?: string
}

export function validateProjectId(projectId: string): FieldValidation {
  const value = projectId.trim()
  if (!value) return { valid: false, error: 'Project ID is required' }
  if (!PROJECT_ID_PATTERN.test(value)) {
    return {
      valid: false,
      error: 'Must start with a letter; lowercase letters, numbers, underscores, and hyphens only',
    }
  }
  return { valid: true }
}

export function validatePrefix(prefix: string): FieldValidation {
  const value = prefix.trim().toUpperCase()
  if (!value) return { valid: false, error: 'Prefix is required' }
  if (!PREFIX_PATTERN.test(value)) {
    return { valid: false, error: 'Prefix must be exactly 3 uppercase letters (e.g. DVP)' }
  }
  return { valid: true }
}

export function validateSummary(summary: string): FieldValidation {
  const value = summary.trim()
  if (!value) return { valid: false, error: 'Summary is required' }
  if (value.length > 500) return { valid: false, error: 'Summary must be at most 500 characters' }
  return { valid: true }
}

export function validateRepo(repo: string): FieldValidation {
  const value = repo.trim()
  if (!value) return { valid: true }
  try {
    new URL(value)
    return { valid: true }
  } catch {
    return { valid: false, error: 'Repository URL must be a valid URL (e.g. https://github.com/user/repo)' }
  }
}
