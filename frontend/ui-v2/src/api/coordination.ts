/**
 * Coordination monitor reads (ENC-TSK-L34 / B67 PWA2.0).
 *
 * Scope: CRQ (coordination-request) documents + session/agent-type/lesson/
 * escalation records. These are served by a DISTINCT, smaller backend slice
 * (comp-coordination-api) — NOT the tracker/documents corpus, the OpenSearch
 * index, or /feed/corpus. Follows the src/api/projects.ts fetcher pattern
 * (bare fetch is permitted anywhere under src/api/, per AC-13's eslint carve-out).
 *
 * Route contracts (documented precisely — ENC-TSK-L36's Agent detail page
 * depends on fetchAgentSessions):
 *
 *   GET /api/v1/coordination/monitor
 *     -> { success, generated_at, requests: CoordinationRequest[], count }
 *
 *   GET /api/v1/coordination/agents/sessions?agent_type_id=<id>&status=<allocated|claimed|retired>
 *     -> { sessions: AgentSession[], count }
 *     (no top-level "success" key — this route predates the envelope convention;
 *     ENC-TSK-I38/J43 handler, only just wired to API Gateway by this task.)
 *
 *   GET /api/v1/coordination/agents/types?status=<active|deprecated>
 *     -> { agent_types: AgentType[], count }
 *
 *   GET /api/v1/tracker/{projectId}?type=lesson&status=<status>
 *     -> { success, records: LessonRecord[], count, page_size, next_cursor? }
 *     (the existing generic tracker list route — lessons ARE tracker records,
 *     just not part of this page's own coordination-api slice.)
 *
 *   GET /api/v1/coordination/escalations?project_id=<id>&status=<status>
 *     -> { success, project_id, pending: EscalationRecord[], terminal: EscalationRecord[], count }
 */

import { API_BASE, SessionExpiredError } from './client'

function jsonHeaders(): HeadersInit {
  return { accept: 'application/json', 'x-requested-with': 'XMLHttpRequest' }
}

export class CoordinationFetchError extends Error {
  readonly status: number
  constructor(status: number, message: string) {
    super(message)
    this.name = 'CoordinationFetchError'
    this.status = status
  }
}

async function getJson<T>(url: string, init?: { signal?: AbortSignal }): Promise<T> {
  const res = await fetch(url, {
    signal: init?.signal,
    credentials: 'include',
    cache: 'no-store',
    headers: jsonHeaders(),
  })
  if (res.status === 401) throw new SessionExpiredError()
  if (!res.ok) throw new CoordinationFetchError(res.status, `Request failed (${res.status}): ${url}`)
  return (await res.json()) as T
}

// ---------------------------------------------------------------------------
// CRQ (coordination request) documents
// ---------------------------------------------------------------------------

export interface CoordinationRequest {
  request_id: string
  project_id: string
  initiative_title: string
  state: string
  execution_mode: string | null
  outcomes: string[]
  requestor_session_id: string | null
  related_record_ids: string[]
  created_at: string
  updated_at: string
  state_history_count: number
  dispatch_attempts: number
}

interface CoordinationMonitorResponse {
  success: boolean
  generated_at: string
  requests: CoordinationRequest[]
  count: number
}

export async function fetchCoordinationRequests(
  init?: { signal?: AbortSignal },
): Promise<CoordinationRequest[]> {
  const body = await getJson<CoordinationMonitorResponse>(
    `${API_BASE}/coordination/monitor`,
    init,
  )
  return body.requests ?? []
}

// ---------------------------------------------------------------------------
// Agent sessions (ENC-SES-NNN) — comp-coordination-api, agent-sessions table
// ---------------------------------------------------------------------------

export type AgentSessionStatus = 'allocated' | 'claimed' | 'retired'

export interface AgentSession {
  session_id: string
  agent_type_id: string
  parent_session_id: string
  runtime: string
  created_at: string
  claimed_at: string
  status: AgentSessionStatus
  credential_id?: string
}

interface AgentSessionsResponse {
  sessions: AgentSession[]
  count: number
}

export interface AgentSessionsQuery {
  agentTypeId?: string
  status?: AgentSessionStatus
}

/**
 * GET /api/v1/coordination/agents/sessions. Shared contract with ENC-TSK-L36's
 * Agent detail page — call with `{ agentTypeId, status: 'claimed' }` to get the
 * "sessions of this agent type currently claimed and not retired" list.
 */
export async function fetchAgentSessions(
  query: AgentSessionsQuery = {},
  init?: { signal?: AbortSignal },
): Promise<AgentSession[]> {
  const qs = new URLSearchParams()
  if (query.agentTypeId) qs.set('agent_type_id', query.agentTypeId)
  if (query.status) qs.set('status', query.status)
  const suffix = qs.toString()
  const body = await getJson<AgentSessionsResponse>(
    `${API_BASE}/coordination/agents/sessions${suffix ? `?${suffix}` : ''}`,
    init,
  )
  return body.sessions ?? []
}

// ---------------------------------------------------------------------------
// Agent types (ENC-AGT-NNN) — comp-coordination-api, agent-types table
// ---------------------------------------------------------------------------

export type AgentTypeStatus = 'active' | 'deprecated'

export interface AgentType {
  agent_type_id: string
  surface: string
  model: string
  cost_tier: string
  status: AgentTypeStatus
  usage_count: number
}

interface AgentTypesResponse {
  agent_types: AgentType[]
  count: number
}

export async function fetchAgentTypes(
  status?: AgentTypeStatus,
  init?: { signal?: AbortSignal },
): Promise<AgentType[]> {
  const qs = status ? `?status=${encodeURIComponent(status)}` : ''
  const body = await getJson<AgentTypesResponse>(
    `${API_BASE}/coordination/agents/types${qs}`,
    init,
  )
  return body.agent_types ?? []
}

// ---------------------------------------------------------------------------
// Lessons — tracker records (record_type=lesson), read via the generic tracker
// list route. Lessons ARE part of the tracker corpus (unlike sessions/agent
// types/escalations), but this page surfaces them alongside those for a single
// coordination-monitor view per the ENC-TSK-L34 AC.
// ---------------------------------------------------------------------------

export interface LessonRecord {
  item_id: string
  project_id: string
  title: string
  status: string
  provenance: string
  created_at: string
  updated_at: string
}

interface TrackerListResponse {
  success: boolean
  records: LessonRecord[]
  count: number
}

export async function fetchLessons(
  projectId: string,
  init?: { signal?: AbortSignal },
): Promise<LessonRecord[]> {
  const body = await getJson<TrackerListResponse>(
    `${API_BASE}/tracker/${encodeURIComponent(projectId)}?type=lesson&page_size=200`,
    init,
  )
  return body.records ?? []
}

// ---------------------------------------------------------------------------
// Escalations — TRACKER_TABLE record_type=escalation, coordination_api's
// human-approval-queue view (Cognito-session-only).
// ---------------------------------------------------------------------------

export interface EscalationRecord {
  item_id?: string
  record_id?: string
  status: string
  target_record_id?: string
  created_at: string
  [key: string]: unknown
}

interface EscalationsResponse {
  success: boolean
  project_id: string
  pending: EscalationRecord[]
  terminal: EscalationRecord[]
  count: number
}

export async function fetchEscalations(
  projectId: string,
  init?: { signal?: AbortSignal },
): Promise<EscalationRecord[]> {
  const body = await getJson<EscalationsResponse>(
    `${API_BASE}/coordination/escalations?project_id=${encodeURIComponent(projectId)}`,
    init,
  )
  return [...(body.pending ?? []), ...(body.terminal ?? [])]
}
