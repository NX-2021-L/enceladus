/**
 * Component registry reads (ENC-TSK-S81, ENC-PLN-107). Read-only.
 *
 *   GET /api/v1/coordination/components        -> { success, components: RegistryComponent[], count }
 *   GET /api/v1/coordination/components/{id}   -> { success, component: RegistryComponent }
 *
 * Same fetch helper and base as src/api/coordination.ts. Ported from frontend/ui/src/api/components.ts.
 */
import { API_BASE, SessionExpiredError } from './client'

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
