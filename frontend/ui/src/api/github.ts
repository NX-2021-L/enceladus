/**
 * github.ts — GitHub integration API for the Enceladus PWA.
 *
 * Sends POST requests to /api/v1/github/issues to create GitHub issues
 * via the devops-github-integration Lambda.
 *
 * Part of ENC-FTR-021 Phase 2 (ENC-TSK-576).
 */

import { refreshCredentials } from './auth'

const GITHUB_BASE = import.meta.env.VITE_GITHUB_API_BASE_URL ?? '/api/v1/github'

export interface CreateIssueRequest {
  owner: string
  repo: string
  title: string
  body?: string
  labels?: string[]
  record_id?: string
  project_id?: string
}

export interface CreateIssueResult {
  success: boolean
  issue_url: string
  issue_number: number
  repo: string
  title: string
  record_id?: string
}

const MAX_CYCLES = 2
const CYCLE_TIMEOUT_MS = 15_000

export async function createGitHubIssue(req: CreateIssueRequest): Promise<CreateIssueResult> {
  const url = `${GITHUB_BASE}/issues`

  for (let cycle = 1; cycle <= MAX_CYCLES; cycle++) {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), CYCLE_TIMEOUT_MS)

    try {
      const res = await fetch(url, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
        signal: controller.signal,
      })
      clearTimeout(timeout)

      if (res.status === 401 && cycle < MAX_CYCLES) {
        await refreshCredentials()
        continue
      }

      const data = await res.json().catch(() => ({ error: `HTTP ${res.status}` }))

      if (!res.ok) {
        throw new Error(data?.error ?? `GitHub API returned ${res.status}`)
      }

      return data as CreateIssueResult
    } catch (err) {
      clearTimeout(timeout)
      if (cycle === MAX_CYCLES) throw err
      await refreshCredentials()
    }
  }

  throw new Error('GitHub issue creation failed after retries')
}
