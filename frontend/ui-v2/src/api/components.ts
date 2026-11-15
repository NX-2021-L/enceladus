/**
 * Component registry reads (ENC-TSK-S81, ENC-PLN-107). Read-only.
 *
 *   GET /api/v1/coordination/components        -> { success, components: RegistryComponent[], count }
 *   GET /api/v1/coordination/components/{id}   -> { success, component: RegistryComponent }
 *
 * Same fetch helper and base as src/api/coordination.ts. Ported from frontend/ui/src/api/components.ts.
 */
import { API_BASE, SessionExpiredError } from './client'
import { ApprovalDecisionError, type ApprovalAdapter, type Verdict } from '../approvals/types'

export type ComponentStatus = 'active' | 'deprecated' | 'archived'
export type ComponentCategory = 'lambda' | 'frontend' | 'infrastructure' | 'library' | 'workflow' | 'external'

/** The eight governed lifecycle statuses (ENC-FTR-076 v2). */
export type ComponentLifecycleStatus =
  | 'proposed' | 'approved' | 'designed' | 'development' | 'production' | 'code-red' | 'deprecated' | 'archived'

export interface RegistryComponent {
  component_id: string
  component_name: string
  project_id: string
  category: ComponentCategory | string
  transition_type?: string
  description?: string
  github_repo?: string
  status?: ComponentStatus | string
  created_at?: string
  updated_at?: string
  lifecycle_status?: ComponentLifecycleStatus | string
  required_transition_type?: string
  alarm_arn?: string
  record_kind?: string
  reverted_at?: string
  reverted_reason?: string
  reverted_by?: string
  approved_at?: string
  approved_by?: string
  deprecated_at?: string
  deprecated_by?: string
  deprecated_reason?: string
  restored_at?: string
  restored_by?: string
}

export class ComponentsFetchError extends Error {
  readonly status: number
  constructor(status: number, message: string) {
    super(message)
    this.name = 'ComponentsFetchError'
    this.status = status
  }
}

async function getJson<T>(url: string, init?: { signal?: AbortSignal }): Promise<T> {
  const res = await fetch(url, {
    signal: init?.signal,
    credentials: 'include',
    cache: 'no-store',
    headers: { accept: 'application/json', 'x-requested-with': 'XMLHttpRequest' },
  })
  if (res.status === 401) throw new SessionExpiredError()
  if (!res.ok) throw new ComponentsFetchError(res.status, `Request failed (${res.status}): ${url}`)
  return (await res.json()) as T
}

export async function listComponents(init?: { signal?: AbortSignal }): Promise<RegistryComponent[]> {
  const body = await getJson<{ components?: RegistryComponent[] }>(`${API_BASE}/coordination/components`, init)
  return body.components ?? []
}

export async function getComponent(id: string, init?: { signal?: AbortSignal }): Promise<RegistryComponent> {
  const body = await getJson<{ component?: RegistryComponent }>(
    `${API_BASE}/coordination/components/${encodeURIComponent(id)}`,
    init,
  )
  if (!body.component) throw new ComponentsFetchError(404, `Component not found: ${id}`)
  return body.component
}

/* ---- Proposals (ENC-TSK-S84; contract ENC-TSK-S82 slice 2) ---------------------------------------------------- */

/** A pending proposal. `component_id` here is the proposal ref (cprop-...), never a component ID. */
export interface ComponentProposal {
  component_id: string
  component_name: string
  suggested_component_id?: string
  project_id: string
  category: string
  requested_minimum_transition_type?: string
  source_paths?: Record<string, string>
  proposing_agent_session_id?: string
  proposed_at?: string
  version: number
  proposal_status?: string
  approved_component_id?: string
  rejection_reason?: string
}

export type ComponentFloor = 'code' | 'external_deploy' | 'documentation'
export const COMPONENT_ID_PATTERN = /^comp-[a-z0-9][a-z0-9-]*$/
export const MIN_REJECT_REASON = 10

export type ProposalPayload =
  | { verdict: 'approve'; component_id: string; required_transition_type: ComponentFloor }
  | { verdict: 'reject'; rejection_reason: string }

const PROPOSALS_URL = `${API_BASE}/coordination/components?kind=proposal&proposal_status=pending`

export async function listPendingProposals(init?: { signal?: AbortSignal }): Promise<ComponentProposal[]> {
  const body = await getJson<{ components?: ComponentProposal[] }>(PROPOSALS_URL, init)
  return body.components ?? []
}

/** POST a decision with If-Match bound to the proposal version. 412 carries the refreshed proposal when the API sends one. */
export async function decideProposal(
  item: ComponentProposal,
  verdict: Verdict,
  payload: ProposalPayload,
): Promise<{ component_id?: string; proposal_status?: string }> {
  const body = verdict === 'approve'
    ? { component_id: (payload as { component_id: string }).component_id, required_transition_type: (payload as { required_transition_type: string }).required_transition_type }
    : { rejection_reason: (payload as { rejection_reason: string }).rejection_reason }
  const res = await fetch(`${API_BASE}/coordination/components/${encodeURIComponent(item.component_id)}/${verdict}`, {
    method: 'POST',
    credentials: 'include',
    cache: 'no-store',
    headers: {
      accept: 'application/json', 'content-type': 'application/json', 'x-requested-with': 'XMLHttpRequest',
      'If-Match': String(item.version),
    },
    body: JSON.stringify(body),
  })
  if (res.status === 401) throw new SessionExpiredError()
  const json = (await res.json().catch(() => ({}))) as Record<string, unknown>
  if (!res.ok) {
    const message = typeof json.error === 'string' ? json.error : typeof json.message === 'string' ? json.message : `Request failed (${res.status})`
    const fresh = (json.proposal ?? json.current ?? json.component) as ComponentProposal | undefined
    throw new ApprovalDecisionError<ComponentProposal>(res.status, message, res.status === 412 ? fresh : undefined)
  }
  const c = (json.component ?? json) as Record<string, unknown>
  return {
    component_id: (json.approved_component_id ?? c.approved_component_id ?? c.component_id) as string | undefined,
    proposal_status: (json.proposal_status ?? c.proposal_status) as string | undefined,
  }
}

export const componentProposalAdapter: ApprovalAdapter<ComponentProposal, ProposalPayload, { component_id?: string; proposal_status?: string }> = {
  list: () => listPendingProposals(),
  key: (i) => i.component_id,
  version: (i) => i.version,
  decide: (item, verdict, payload) => decideProposal(item, verdict, payload),
}
