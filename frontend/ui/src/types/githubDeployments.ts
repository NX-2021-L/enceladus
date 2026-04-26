// GitHub Deployments + Actions API types for DM Gen2 thin reader (ENC-TSK-F62).

export interface GitHubDeployment {
  id: number
  sha: string
  ref: string
  task: string
  environment: string
  description: string | null
  created_at: string
  updated_at: string
  statuses_url: string
  url: string
  creator: {
    login: string
    html_url: string
  }
  payload: Record<string, unknown> | string
}

export interface GitHubDeploymentStatus {
  id: number
  state: 'error' | 'failure' | 'inactive' | 'in_progress' | 'queued' | 'pending' | 'success'
  description: string | null
  environment_url: string | null
  log_url: string | null
  created_at: string
}

export interface GitHubWorkflowRun {
  id: number
  name: string
  head_sha: string
  head_branch: string
  status: 'queued' | 'in_progress' | 'completed' | null
  conclusion: 'success' | 'failure' | 'cancelled' | 'skipped' | null
  html_url: string
  run_number: number
  created_at: string
  head_commit: {
    message: string
    author: { name: string }
  }
}

// Design system status tokens (ENC-TSK-F62 AC-5)
export type DesignSystemStatus = 'open' | 'in-progress' | 'blocked' | 'closed'

export function githubStateToDesignStatus(
  state: GitHubDeploymentStatus['state'],
): DesignSystemStatus {
  switch (state) {
    case 'pending':
    case 'queued':
      return 'open'
    case 'in_progress':
      return 'in-progress'
    case 'error':
    case 'failure':
      return 'blocked'
    case 'success':
    case 'inactive':
      return 'closed'
    default:
      return 'open'
  }
}

export interface DeploymentWithStatus {
  deployment: GitHubDeployment
  latestStatus: GitHubDeploymentStatus | null
  designStatus: DesignSystemStatus
  run: GitHubWorkflowRun | null
}
