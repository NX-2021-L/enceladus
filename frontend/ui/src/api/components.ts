/**
 * components.ts — API client for component registry endpoints (ENC-FTR-041)
 *
 * Routes: GET/POST/PATCH/DELETE /api/v1/coordination/components
 * Read  operations: no auth required (internal key not needed from PWA)
 * Write operations: require Cognito auth — credentials:'include' sends the session cookie.
 *   - transition_type updates additionally require Cognito (enforced by Lambda)
 */

export type ComponentStatus = 'active' | 'deprecated' | 'archived'
export type ComponentCategory =
  | 'lambda'
  | 'frontend'
  | 'infrastructure'
  | 'library'
  | 'workflow'
  | 'external'
export type ComponentTransitionType =
  | 'github_pr_deploy'
  | 'lambda_deploy'
  | 'web_deploy'
  | 'code_only'
  | 'no_code'

// ENC-FTR-076 v2 / DOC-546B896390EA §3 — 8-status lifecycle.
// Source of truth: governance_data_dictionary.json v2026-04-19.04
//   entities.component_registry.component.fields.lifecycle_status
export type ComponentLifecycleStatus =
  | 'proposed'
  | 'approved'
  | 'designed'
  | 'development'
  | 'production'
  | 'code-red'
  | 'deprecated'
  | 'archived'

export interface RegistryComponent {
  component_id: string
  component_name: string
  project_id: string
  category: ComponentCategory
  transition_type: ComponentTransitionType
  description: string
  github_repo?: string
  status: ComponentStatus
  created_at: string
  updated_at: string
  // --- ENC-FTR-076 v2 fields (optional for backward compat with v1 records) ---
  lifecycle_status?: ComponentLifecycleStatus
  // Governed strictness (DOC-546B896390EA §6). `transition_type` remains the
  // legacy write-path field; `required_transition_type` is the v2 override.
  required_transition_type?: ComponentTransitionType
  // Optional CloudWatch alarm hook (DOC-546B896390EA §8 — v5 scaffolding).
  alarm_arn?: string
  // Revert metadata (archived via revert modal)
  reverted_at?: string
  reverted_reason?: string
  reverted_by?: string
  // Approve / deprecate / restore metadata (may be absent on pre-v2 records)
  approved_at?: string
  approved_by?: string
  deprecated_at?: string
  deprecated_by?: string
  deprecated_reason?: string
  restored_at?: string
  restored_by?: string
}

export interface ComponentFilters {
  project_id?: string
  category?: ComponentCategory | ''
  status?: ComponentStatus | ''
}

export interface ComponentsListResponse {
  success: boolean
  components: RegistryComponent[]
  count: number
}

const BASE = '/api/v1/coordination'

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    credentials: 'include',
    ...init,
  })
  if (!resp.ok) {
    const body = (await resp.json().catch(() => ({}))) as Record<string, unknown>
    throw new Error(String(body.error ?? body.message ?? `HTTP ${resp.status}`))
  }
  return resp.json() as Promise<T>
}

export async function fetchComponents(
  filters: ComponentFilters = {},
): Promise<ComponentsListResponse> {
  const params = new URLSearchParams()
  if (filters.project_id) params.set('project_id', filters.project_id)
  if (filters.category) params.set('category', filters.category)
  if (filters.status) params.set('status', filters.status)
  const qs = params.toString()
  return apiFetch<ComponentsListResponse>(`/components${qs ? `?${qs}` : ''}`)
}

export async function fetchComponent(
  componentId: string,
): Promise<{ success: boolean; component: RegistryComponent }> {
  return apiFetch<{ success: boolean; component: RegistryComponent }>(
    `/components/${componentId}`,
  )
}

export type CreateComponentInput = {
  component_id: string
  component_name: string
  project_id: string
  category: ComponentCategory
  transition_type: ComponentTransitionType
  description: string
  github_repo?: string
  status?: ComponentStatus
}

export async function createComponent(
  data: CreateComponentInput,
): Promise<{ success: boolean; component: RegistryComponent }> {
  return apiFetch<{ success: boolean; component: RegistryComponent }>(`/components`, {
    method: 'POST',
    body: JSON.stringify(data),
  })
}

export type UpdateComponentInput = Partial<
  Pick<
    RegistryComponent,
    | 'component_name'
    | 'category'
    | 'transition_type'
    | 'description'
    | 'github_repo'
    | 'status'
    | 'project_id'
  >
>

export async function updateComponent(
  componentId: string,
  data: UpdateComponentInput,
): Promise<{ success: boolean; component: RegistryComponent }> {
  return apiFetch<{ success: boolean; component: RegistryComponent }>(
    `/components/${componentId}`,
    {
      method: 'PATCH',
      body: JSON.stringify(data),
    },
  )
}

export async function deleteComponent(componentId: string): Promise<void> {
  await apiFetch<{ success: boolean }>(`/components/${componentId}`, {
    method: 'DELETE',
  })
}

// ENC-FTR-076 Phase 6: Component proposal types and approval/rejection API
// ENC-FTR-076 v2 / ENC-TSK-F44: extended with required_transition_type,
// alarm_arn, revert/deprecate/restore/advance operations.

export interface ComponentProposal {
  component_id: string
  component_name: string
  project_id: string
  category: ComponentCategory
  description: string
  source_paths: string[]
  proposing_agent_session_id: string
  requested_minimum_transition_type: ComponentTransitionType
  // Optional v2 field — proposing agent may request a stricter required type.
  // Absent on pre-v2 proposals; approve modal falls back to minimum.
  requested_required_transition_type?: ComponentTransitionType
  lifecycle_status: 'proposed'
  created_at: string
  updated_at: string
}

export interface ApproveComponentInput {
  id: string
  // Optional: io may override minimum_transition_type (legacy write field)
  minimum_transition_type?: ComponentTransitionType
  // Optional: io may override required_transition_type (v2 strictness)
  required_transition_type?: ComponentTransitionType
  // Optional: io may attach a CloudWatch alarm ARN (DOC-546B896390EA §8 v5 scaffold)
  alarm_arn?: string
}

// Legacy Phase 6 reject — preserved for backward compat while F40 ships.
export interface RejectComponentInput {
  id: string
  rejection_reason: string
}

// ENC-FTR-076 v2 / AC[3]-d — revert is terminal (archives component).
export interface RevertComponentInput {
  id: string
  reverted_reason: string
}

// ENC-FTR-076 v2 / AC[3]-e — deprecate (io only, Cognito-gated).
export interface DeprecateComponentInput {
  id: string
  deprecated_reason?: string
}

// ENC-FTR-076 v2 / AC[3]-e — restore deprecated → production (io only).
export interface RestoreComponentInput {
  id: string
}

// ENC-FTR-076 v2 — advance lifecycle (approved → designed → development → production).
// Target resolved server-side based on current lifecycle_status.
export interface AdvanceComponentInput {
  id: string
  target_lifecycle_status?: ComponentLifecycleStatus
}

export async function approveComponent(
  input: ApproveComponentInput,
): Promise<{ success: boolean }> {
  const body: Record<string, string> = {}
  if (input.minimum_transition_type) {
    body.transition_type = input.minimum_transition_type
  }
  if (input.required_transition_type) {
    body.required_transition_type = input.required_transition_type
  }
  if (input.alarm_arn && input.alarm_arn.trim()) {
    body.alarm_arn = input.alarm_arn.trim()
  }
  return apiFetch<{ success: boolean }>(`/components/${input.id}/approve`, {
    method: 'POST',
    body: JSON.stringify(body),
  })
}

export async function rejectComponent(
  input: RejectComponentInput,
): Promise<{ success: boolean }> {
  return apiFetch<{ success: boolean }>(`/components/${input.id}/reject`, {
    method: 'POST',
    body: JSON.stringify({ rejection_reason: input.rejection_reason }),
  })
}

export async function revertComponent(
  input: RevertComponentInput,
): Promise<{ success: boolean }> {
  return apiFetch<{ success: boolean }>(`/components/${input.id}/revert`, {
    method: 'POST',
    body: JSON.stringify({ reverted_reason: input.reverted_reason }),
  })
}

export async function deprecateComponent(
  input: DeprecateComponentInput,
): Promise<{ success: boolean }> {
  const body: Record<string, string> = {}
  if (input.deprecated_reason && input.deprecated_reason.trim()) {
    body.deprecated_reason = input.deprecated_reason.trim()
  }
  return apiFetch<{ success: boolean }>(`/components/${input.id}/deprecate`, {
    method: 'POST',
    body: JSON.stringify(body),
  })
}

export async function restoreComponent(
  input: RestoreComponentInput,
): Promise<{ success: boolean }> {
  return apiFetch<{ success: boolean }>(`/components/${input.id}/restore`, {
    method: 'POST',
    body: JSON.stringify({}),
  })
}

export async function advanceComponent(
  input: AdvanceComponentInput,
): Promise<{ success: boolean }> {
  const body: Record<string, string> = {}
  if (input.target_lifecycle_status) {
    body.target_lifecycle_status = input.target_lifecycle_status
  }
  return apiFetch<{ success: boolean }>(`/components/${input.id}/advance`, {
    method: 'POST',
    body: JSON.stringify(body),
  })
}

// React-Query key factory
export const componentKeys = {
  all: ['components'] as const,
  list: (filters: ComponentFilters) => ['components', 'list', filters] as const,
  detail: (id: string) => ['components', 'detail', id] as const,
}
