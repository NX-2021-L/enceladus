/**
 * Coordination-api agent session/type reads (ENC-TSK-L36 — Agent detail page).
 *
 * Served by the same coordination-api list route as L34:
 *   GET /api/v1/coordination/agents/sessions?agent_type_id=<id>&status=claimed
 *     -> { sessions: AgentSession[], count: number }   (no top-level "success" key)
 *   GET /api/v1/coordination/agents/types?status=active
 *     -> { agent_types: AgentType[], count: number }
 *
 * NOTE: this file is intentionally self-contained rather than importing from
 * an L34-branch `api/coordination.ts` module, since that file does not exist
 * in this branch's ancestry yet. During central integration this should be
 * reconciled/de-duplicated with L34's equivalent fetcher(s) if one lands with
 * overlapping shape.
 */

import { API_BASE, SessionExpiredError } from './client'

export type AgentSessionStatus = 'claimed' | 'retired' | string

export interface AgentSession {
  session_id: string
  agent_type_id: string
  parent_session_id?: string | null
  runtime?: string
  created_at?: string
  claimed_at?: string
  status: AgentSessionStatus
  credential_id?: string
}

export interface AgentSessionsListResponse {
  sessions: AgentSession[]
  count: number
}

export interface AgentType {
  agent_type_id: string
  surface?: string
  model?: string
  cost_tier?: string
  status?: string
  usage_count?: number
}

export interface AgentTypesListResponse {
  agent_types: AgentType[]
  count: number
}

export class AgentSessionsFetchError extends Error {
  readonly status: number
  constructor(status: number, message: string) {
    super(message)
    this.name = 'AgentSessionsFetchError'
    this.status = status
  }
}

interface FetchInit {
  signal?: AbortSignal
}

function defaultHeaders(): HeadersInit {
  return {
    accept: 'application/json',
    'x-requested-with': 'XMLHttpRequest',
  }
}

/**
 * List sessions of a given agent type filtered by status. For the "currently
 * claimed and not retired" AC, callers pass status='claimed' — retired
 * sessions carry a distinct status value and are excluded by the filter.
 */
export async function fetchAgentSessions(
  agentTypeId: string,
  status: AgentSessionStatus = 'claimed',
  init?: FetchInit,
): Promise<AgentSession[]> {
  const qs = new URLSearchParams({ agent_type_id: agentTypeId, status })
  const url = `${API_BASE}/coordination/agents/sessions?${qs.toString()}`
  const res = await fetch(url, {
    signal: init?.signal,
    credentials: 'include',
    cache: 'no-store',
    headers: defaultHeaders(),
  })
  if (res.status === 401) throw new SessionExpiredError()
  if (!res.ok) {
    throw new AgentSessionsFetchError(res.status, `Failed to list agent sessions (${res.status})`)
  }
  const body = (await res.json()) as AgentSessionsListResponse
  return body.sessions ?? []
}

/** List agent types, used to resolve/display agent_type metadata alongside sessions. */
export async function fetchAgentTypes(
  status = 'active',
  init?: FetchInit,
): Promise<AgentType[]> {
  const qs = new URLSearchParams({ status })
  const url = `${API_BASE}/coordination/agents/types?${qs.toString()}`
  const res = await fetch(url, {
    signal: init?.signal,
    credentials: 'include',
    cache: 'no-store',
    headers: defaultHeaders(),
  })
  if (res.status === 401) throw new SessionExpiredError()
  if (!res.ok) {
    throw new AgentSessionsFetchError(res.status, `Failed to list agent types (${res.status})`)
  }
  const body = (await res.json()) as AgentTypesListResponse
  return body.agent_types ?? []
}
