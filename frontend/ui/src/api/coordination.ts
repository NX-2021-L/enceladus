import type { CoordinationMonitorResponse, CoordinationDetailResponse } from '../types/coordination'
import { fetchWithAuth } from './client'

export const coordinationKeys = {
  list: ['coordination', 'list'] as const,
  detail: (requestId: string) => ['coordination', 'detail', requestId] as const,
}

export async function fetchCoordinationList(): Promise<CoordinationMonitorResponse> {
  const res = await fetchWithAuth('/api/v1/coordination/monitor')
  if (!res.ok) throw new Error(`Failed to fetch coordination requests: ${res.status}`)
  return res.json()
}

export async function fetchCoordinationRequest(requestId: string): Promise<CoordinationDetailResponse> {
  const res = await fetchWithAuth(`/api/v1/coordination/monitor/${requestId}`)
  if (!res.ok) throw new Error(`Failed to fetch coordination request: ${res.status}`)
  return res.json()
}
