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
  edges?: ComponentEdge[]
}

/** A forward edge from the component to a task. S82 _component_edges_view returns { edge_type, task_id, created_at, locked, lock_trigger } as a sibling of `component` in GET /components/{id}. */
export interface ComponentEdge {
  edge_type?: string
  task_id?: string
  created_at?: string
  locked?: boolean
  lock_trigger?: string | null
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
  const body = await getJson<{ component?: RegistryComponent; edges?: ComponentEdge[] }>(
    `${API_BASE}/coordination/components/${encodeURIComponent(id)}`,
    init,
  )
  if (!body.component) throw new ComponentsFetchError(404, `Component not found: ${id}`)
  return body.edges ? { ...body.component, edges: body.edges } : body.component
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

/** The S82 proposal view uses proposal_ref/display_name and a list for source_paths; map it onto ComponentProposal. */
export function toProposal(raw: Record<string, unknown>): ComponentProposal {
  const sp = raw.source_paths
  return {
    ...(raw as unknown as ComponentProposal),
    component_id: String(raw.proposal_ref ?? raw.component_id ?? ''),
    component_name: String(raw.display_name ?? raw.component_name ?? ''),
    source_paths: Array.isArray(sp) ? Object.fromEntries(sp.map((v, i) => [String(i), String(v)])) : (sp as Record<string, string> | undefined),
    version: Number(raw.version ?? 1),
  }
}

const PROPOSALS_URL = `${API_BASE}/coordination/components?kind=proposal&proposal_status=pending`

export async function listPendingProposals(init?: { signal?: AbortSignal }): Promise<ComponentProposal[]> {
  const body = await getJson<{ proposals?: Record<string, unknown>[]; components?: Record<string, unknown>[] }>(PROPOSALS_URL, init)
  return (body.proposals ?? body.components ?? []).map(toProposal)
}

/** One proposal by ref (GET /components/{ref} returns { proposal } for a cprop- ref). */
export async function getProposal(ref: string, init?: { signal?: AbortSignal }): Promise<ComponentProposal> {
  const body = await getJson<{ proposal?: Record<string, unknown> }>(`${API_BASE}/coordination/components/${encodeURIComponent(ref)}`, init)
  if (!body.proposal) throw new ComponentsFetchError(404, `Proposal not found: ${ref}`)
  return toProposal(body.proposal)
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
    const rawFresh = (json.proposal ?? json.current) as Record<string, unknown> | undefined
    const fresh = rawFresh ? toProposal(rawFresh) : undefined
    throw new ApprovalDecisionError<ComponentProposal>(res.status, message, res.status === 412 ? fresh : undefined)
  }
  const c = ((typeof json.component === 'object' ? json.component : null) ?? json) as Record<string, unknown>
  return {
    component_id: (json.approved_component_id ?? c.approved_component_id ?? json.component_id ?? c.component_id) as string | undefined,
    proposal_status: (json.proposal_status ?? c.proposal_status) as string | undefined,
  }
}

export const componentProposalAdapter: ApprovalAdapter<ComponentProposal, ProposalPayload, { component_id?: string; proposal_status?: string }> = {
  list: () => listPendingProposals(),
  key: (i) => i.component_id,
  version: (i) => i.version,
  decide: (item, verdict, payload) => decideProposal(item, verdict, payload),
}

/* ---- Lifecycle actions and registration (ENC-TSK-S84 slice 2) ------------------------------------------------ */

export type LifecycleAction = 'advance' | 'revert' | 'deprecate' | 'restore'
export const MIN_REVERT_REASON = 10

async function postJson(url: string, body: unknown): Promise<Record<string, unknown>> {
  const res = await fetch(url, {
    method: 'POST', credentials: 'include', cache: 'no-store',
    headers: { accept: 'application/json', 'content-type': 'application/json', 'x-requested-with': 'XMLHttpRequest' },
    body: JSON.stringify(body),
  })
  if (res.status === 401) throw new SessionExpiredError()
  const json = (await res.json().catch(() => ({}))) as Record<string, unknown>
  if (!res.ok) {
    const message = typeof json.error === 'string' ? json.error : typeof json.message === 'string' ? json.message : `Request failed (${res.status})`
    throw new ComponentsFetchError(res.status, message)
  }
  return json
}

/** Body keys per the S82 handlers: advance {target_status}, revert {reverted_reason}, deprecate {reason?}, restore {}. */
export function lifecycleBody(action: LifecycleAction, arg?: string): Record<string, string> {
  if (action === 'advance') return { target_status: arg ?? '' }
  if (action === 'revert') return { reverted_reason: (arg ?? '').trim() }
  if (action === 'deprecate') return arg?.trim() ? { reason: arg.trim() } : {}
  return {}
}

export function runLifecycleAction(id: string, action: LifecycleAction, arg?: string) {
  return postJson(`${API_BASE}/coordination/components/${encodeURIComponent(id)}/${action}`, lifecycleBody(action, arg))
}

export interface RegisterInput {
  component_name: string
  project_id: string
  category: string
  required_transition_type: ComponentFloor
  description: string
  component_id?: string
}

export function registerComponent(input: RegisterInput) {
  const body: Record<string, string> = { ...input }
  if (!body.component_id?.trim()) delete body.component_id
  if (!body.description?.trim()) delete body.description
  return postJson(`${API_BASE}/coordination/components`, body)
}
