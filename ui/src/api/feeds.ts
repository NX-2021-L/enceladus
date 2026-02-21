import type { Task, Issue, Feature, ProjectsFeed, TasksFeed, IssuesFeed, FeaturesFeed } from '../types/feeds'
import { fetchFeed, fetchWithAuth } from './client'

const BASE_URL = import.meta.env.VITE_FEED_BASE_URL || '/mobile/v1'

export const feedKeys = {
  projects: ['feed', 'projects'] as const,
  tasks: ['feed', 'tasks'] as const,
  issues: ['feed', 'issues'] as const,
  features: ['feed', 'features'] as const,
  liveFeed: ['feed', 'live'] as const,
  reference: (projectId: string) => ['feed', 'reference', projectId] as const,
}

export interface LiveFeedResponse {
  generated_at: string
  version: string
  tasks: Task[]
  issues: Issue[]
  features: Feature[]
}

export async function fetchLiveFeed(): Promise<LiveFeedResponse> {
  const url = '/api/v1/feed'
  const res = await fetchWithAuth(url)
  if (!res.ok) throw new Error(`Failed to fetch live feed: ${res.status}`)
  return res.json()
}

export const fetchProjects = () => fetchFeed<ProjectsFeed>('projects')
export const fetchTasks = () => fetchFeed<TasksFeed>('tasks')
export const fetchIssues = () => fetchFeed<IssuesFeed>('issues')
export const fetchFeatures = () => fetchFeed<FeaturesFeed>('features')

export async function fetchProjectReference(projectId: string): Promise<string> {
  const url = `${BASE_URL}/reference/${projectId}.md`
  const res = await fetchWithAuth(url, {
    headers: {
      Accept: 'text/markdown,text/plain;q=0.9,*/*;q=0.8',
    },
  })
  if (res.status === 404) throw new Error('Reference document not found for this project')
  if (!res.ok) throw new Error(`Failed to fetch reference: ${res.status}`)
  return res.text()
}
