/**
 * Type definitions for the Deployment Manager — GMF (DOC-63420302EF65 §6).
 */

export interface DeploymentDecision {
  record_id: string
  status: DeploymentStatus
  github_pr_number: number
  github_pr_url: string
  pr_title: string
  pr_author: string
  head_branch: string
  head_sha: string
  original_target: 'prod' | 'gamma' | 'undeclared'
  final_target: string
  generation_id: string
  decided_by: string
  decided_at: string
  decision_reason: string
  deployment_outcome: string
  deployed_at: string
  created_at: string
  related_enceladus_task_ids: string[]
  related_enceladus_feature_ids: string[]
  // ENC-TSK-E57: Deploy approval enforcement fields
  approval_token?: string
  decided_by_email?: string
  bypass_reason?: string
}

export type DeploymentStatus =
  | 'pending_approval'
  | 'awaiting_prod_approval'
  | 'approved'
  | 'diverted'
  | 'reverted'
  | 'deploying'
  | 'deployed'
  | 'failed'

export interface DeployQueueResponse {
  success: boolean
  project_id: string
  count: number
  decisions: DeploymentDecision[]
}

export interface DeployDecideRequest {
  action: 'approve' | 'divert' | 'revert'
  pr_number: number
  project_id?: string
  decision_reason?: string
}

export interface DeployDecideResponse {
  success: boolean
  action: string
  pr_number: number
  merged?: boolean
  merge_sha?: string
  approval_token?: string
  new_base?: string
  closed?: boolean
  decision?: DeploymentDecision
  error?: string
}
