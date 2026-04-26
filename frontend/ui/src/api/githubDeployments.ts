// Direct api.github.com reader for DM Gen2 (ENC-TSK-F62 AC-1, AC-3).
// Token is a GitHub App installation access token vended at runtime by
// GET /api/v1/auth/github-token — no build-time secrets required.

import { getGitHubToken } from './githubToken'
import type {
  GitHubDeployment,
  GitHubDeploymentStatus,
  GitHubWorkflowRun,
} from '../types/githubDeployments'

const REPO = 'NX-2021-L/enceladus'
const GH_API = 'https://api.github.com'

async function headers(): Promise<HeadersInit> {
  const token = await getGitHubToken()
  return {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    Authorization: `Bearer ${token}`,
  }
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${GH_API}${path}`, { headers: await headers(), cache: 'no-store' })
  if (!res.ok) throw new Error(`GitHub API ${res.status} — ${path}`)
  return res.json() as Promise<T>
}

export async function fetchDeployments(limit = 20): Promise<GitHubDeployment[]> {
  return get<GitHubDeployment[]>(
    `/repos/${REPO}/deployments?per_page=${limit}&sort=created&direction=desc`,
  )
}

export async function fetchDeploymentStatuses(
  deploymentId: number,
): Promise<GitHubDeploymentStatus[]> {
  return get<GitHubDeploymentStatus[]>(
    `/repos/${REPO}/deployments/${deploymentId}/statuses?per_page=1`,
  )
}

export async function fetchRecentRuns(limit = 30): Promise<GitHubWorkflowRun[]> {
  const data = await get<{ workflow_runs: GitHubWorkflowRun[] }>(
    `/repos/${REPO}/actions/runs?per_page=${limit}&branch=main`,
  )
  return data.workflow_runs
}
