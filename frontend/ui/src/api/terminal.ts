import type {
  TerminalSessionsResponse,
  TerminalTurnsResponse,
  SendMessageResponse,
} from '../types/terminal'
import { fetchWithAuth } from './client'

export const terminalKeys = {
  sessions: ['terminal', 'sessions'] as const,
  turns: (sessionId: string) => ['terminal', 'turns', sessionId] as const,
  activeRequest: (requestId: string) => ['terminal', 'activeRequest', requestId] as const,
}

export async function fetchTerminalSessions(): Promise<TerminalSessionsResponse> {
  const res = await fetchWithAuth('/api/v1/coordination/sessions')
  if (!res.ok) throw new Error(`Failed to fetch sessions: ${res.status}`)
  return res.json()
}

export async function fetchSessionTurns(sessionId: string): Promise<TerminalTurnsResponse> {
  const res = await fetchWithAuth(`/api/v1/coordination/sessions/${sessionId}/turns`)
  if (!res.ok) throw new Error(`Failed to fetch session turns: ${res.status}`)
  return res.json()
}

export async function sendChatMessage(
  sessionId: string,
  message: string,
  projectId: string,
  provider: string,
): Promise<SendMessageResponse> {
  const res = await fetchWithAuth(`/api/v1/coordination/sessions/${sessionId}/message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, project_id: projectId, provider }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }))
    throw new Error(err?.error ?? `Failed to send message: ${res.status}`)
  }
  return res.json()
}

export async function fetchCoordinationRequestState(
  requestId: string,
): Promise<{ success: boolean; request: { state: string; result?: { summary?: string } } }> {
  const res = await fetchWithAuth(`/api/v1/coordination/monitor/${requestId}`)
  if (!res.ok) throw new Error(`Failed to fetch request state: ${res.status}`)
  return res.json()
}
