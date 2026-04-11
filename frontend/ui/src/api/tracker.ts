import type { Task, Issue, Feature, ProjectSummary } from '../types/feeds'
import { fetchWithAuth } from './client'

const BASE = import.meta.env.VITE_MUTATION_BASE_URL ?? '/api/v1/tracker'

export const trackerKeys = {
  task: (recordId: string) => ['tracker', 'task', recordId] as const,
  issue: (recordId: string) => ['tracker', 'issue', recordId] as const,
  feature: (recordId: string) => ['tracker', 'feature', recordId] as const,
}

async function fetchRecord<T>(projectId: string, recordType: 'task' | 'issue' | 'feature', recordId: string): Promise<T> {
  const url = `${BASE}/${encodeURIComponent(projectId)}/${recordType}/${encodeURIComponent(recordId)}`
  const res = await fetchWithAuth(url)
  if (!res.ok) throw new Error(`Failed to fetch ${recordType} ${recordId}: ${res.status}`)
  const data = await res.json()
  return (data.record ?? data) as T
}

export const fetchTaskById = (projectId: string, recordId: string) =>
  fetchRecord<Task>(projectId, 'task', recordId)

export const fetchIssueById = (projectId: string, recordId: string) =>
  fetchRecord<Issue>(projectId, 'issue', recordId)

export const fetchFeatureById = (projectId: string, recordId: string) =>
  fetchRecord<Feature>(projectId, 'feature', recordId)

export function resolveProjectFromRecordId(
  recordId: string,
  projects: ProjectSummary[],
): string | null {
  const prefix = recordId.split('-')[0]
  if (!prefix) return null
  const match = projects.find((p) => p.prefix === prefix)
  return match?.project_id ?? null
}
