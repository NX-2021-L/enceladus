/**
 * Deploy API module — GMF Deployment Manager (DOC-63420302EF65 §6).
 *
 * Endpoints:
 *   GET  /api/v1/deploy/queue   — pending deployment decisions
 *   POST /api/v1/deploy/decide  — approve/divert/revert a deployment
 */

import type {
  DeployQueueResponse,
  DeployDecideRequest,
  DeployDecideResponse,
} from '../types/deployments'
import { fetchWithAuth } from './client'

export const deployKeys = {
  queue: (projectId: string) => ['deploy', 'queue', projectId] as const,
  history: (projectId: string) => ['deploy', 'history', projectId] as const,
}

export async function fetchDeployQueue(
  projectId: string = 'enceladus',
): Promise<DeployQueueResponse> {
  const res = await fetchWithAuth(
    `/api/v1/deploy/queue?project_id=${encodeURIComponent(projectId)}&limit=50`,
  )
  if (!res.ok) throw new Error(`Failed to fetch deploy queue: ${res.status}`)
  const data: DeployQueueResponse = await res.json()
  // ISS-208 AC3 validation — safe to remove
  // ENC-ISS-208: Strip DynamoDB composite key prefix from record_id.
  // The "decision#" prefix contains a # that breaks native browser
  // input validation (url/email types reject it). The backend
  // reconstructs the full key from pr_number, so the UI never needs it.
  data.decisions = data.decisions.map((d) => ({
    ...d,
    record_id: d.record_id.replace(/^decision#/, ''),
  }))
  return data
}

export async function submitDeployDecision(
  request: DeployDecideRequest,
): Promise<DeployDecideResponse> {
  const res = await fetchWithAuth('/api/v1/deploy/decide', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  })
  const data: DeployDecideResponse = await res.json()
  if (!res.ok || !data.success) {
    throw new Error(data.error || `Deploy decision failed: ${res.status}`)
  }
  // ENC-ISS-208 defense-in-depth: mirror the fetchDeployQueue strip on the
  // mutation response so the full DPL record echoed back to the UI is already
  // prefix-free before it can re-enter React Query cache or any consumer.
  if (data.decision && typeof data.decision.record_id === 'string') {
    data.decision = {
      ...data.decision,
      record_id: data.decision.record_id.replace(/^decision#/, ''),
    }
  }
  return data
}
