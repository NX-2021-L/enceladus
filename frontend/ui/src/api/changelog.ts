import type { ChangelogEntry, ProjectVersion } from '../types/feeds'
import { fetchWithAuth } from './client'

const API_BASE = '/api/v1/changelog'

export const changelogKeys = {
  history: (projectId: string, params?: ChangelogHistoryParams) =>
    ['changelog', 'history', projectId, params] as const,
  historyAll: (projectIds: string[], params?: ChangelogHistoryParams) =>
    ['changelog', 'history-all', projectIds, params] as const,
  version: (projectId: string) => ['changelog', 'version', projectId] as const,
  versions: (projectIds: string[]) => ['changelog', 'versions', projectIds] as const,
}

export interface ChangelogHistoryParams {
  limit?: number
  change_type?: 'major' | 'minor' | 'patch'
}

interface ChangelogHistoryResponse {
  project_id: string
  entries: ChangelogEntry[]
  count: number
}

interface ChangelogHistoryAllResponse {
  entries: ChangelogEntry[]
  count: number
}

export async function fetchChangelogHistory(
  projectId: string,
  params?: ChangelogHistoryParams,
): Promise<ChangelogHistoryResponse> {
  const qs = new URLSearchParams()
  if (params?.limit !== undefined) qs.set('limit', String(params.limit))
  if (params?.change_type) qs.set('change_type', params.change_type)
  const qsStr = qs.toString()
  const url = `${API_BASE}/history/${encodeURIComponent(projectId)}${qsStr ? `?${qsStr}` : ''}`
  const res = await fetchWithAuth(url)
  if (!res.ok) throw new Error(`Failed to fetch changelog history: ${res.status}`)
  const data = await res.json()
  const entries = data.entries ?? []
  return { project_id: projectId, entries, count: data.count ?? entries.length }
}

export async function fetchAllChangelogHistory(
  projectIds: string[],
  params?: ChangelogHistoryParams,
): Promise<ChangelogHistoryAllResponse> {
  const qs = new URLSearchParams()
  qs.set('projects', projectIds.join(','))
  if (params?.limit !== undefined) qs.set('limit', String(params.limit))
  if (params?.change_type) qs.set('change_type', params.change_type)
  const res = await fetchWithAuth(`${API_BASE}/history?${qs.toString()}`)
  if (!res.ok) throw new Error(`Failed to fetch multi-project changelog: ${res.status}`)
  const data = await res.json()
  const entries = data.entries ?? []
  return { entries, count: data.count ?? entries.length }
}

export async function fetchProjectVersion(projectId: string): Promise<ProjectVersion> {
  const res = await fetchWithAuth(`${API_BASE}/version/${encodeURIComponent(projectId)}`)
  if (!res.ok) throw new Error(`Failed to fetch project version: ${res.status}`)
  return res.json()
}

export async function fetchAllVersions(projectIds: string[]): Promise<ProjectVersion[]> {
  const qs = new URLSearchParams({ projects: projectIds.join(',') })
  const res = await fetchWithAuth(`${API_BASE}/versions?${qs.toString()}`)
  if (!res.ok) throw new Error(`Failed to fetch all versions: ${res.status}`)
  const data = await res.json()
  return data.versions ?? []
}
