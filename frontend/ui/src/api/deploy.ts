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
  return res.json()
}

export async function submitDeployDecision(
  request: DeployDecideRequest,
): Promise<DeployDecideResponse> {
  const res = await fetchWithAuth('/api/v1/deploy/decide', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  })
  const data = await res.json()
  if (!res.ok || !data.success) {
    throw new Error(data.error || `Deploy decision failed: ${res.status}`)
  }
  return data
}
