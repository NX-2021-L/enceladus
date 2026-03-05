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

// React-Query key factory
export const componentKeys = {
  all: ['components'] as const,
  list: (filters: ComponentFilters) => ['components', 'list', filters] as const,
  detail: (id: string) => ['components', 'detail', id] as const,
}
