// Direct api.github.com reader for DM Gen2 (ENC-TSK-F62 AC-1, AC-3).
// Zero proxy through Enceladus Lambda. Token (VITE_GITHUB_READ_TOKEN) is a
// read-only fine-grained PAT injected from CI/CD build secrets — not committed
// to source, not a bundle-level hardcode.

import type {
  GitHubDeployment,
  GitHubDeploymentStatus,
  GitHubWorkflowRun,
} from '../types/githubDeployments'

const REPO = 'NX-2021-L/enceladus'
const GH_API = 'https://api.github.com'
const token = import.meta.env.VITE_GITHUB_READ_TOKEN as string | undefined

function headers(): HeadersInit {
  const h: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  }
  if (token) h['Authorization'] = `Bearer ${token}`
  return h
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${GH_API}${path}`, { headers: headers(), cache: 'no-store' })
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
