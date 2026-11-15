/** Component registry view model (ENC-TSK-S81): floor mapping, lifecycle governance check, segments. */
import type { RegistryComponent } from '../api/components'

export const GOVERNED_LIFECYCLE = [
  'proposed', 'approved', 'designed', 'development', 'production', 'code-red', 'deprecated', 'archived',
] as const
export const PIPELINE_STATUSES = ['approved', 'designed', 'development'] as const

export type FloorClass = 'code' | 'external_deploy' | 'documentation' | string

const CODE_TYPES = ['github_pr_deploy', 'lambda_deploy', 'web_deploy', 'code_only', 'data_only', 'code']

/** Governed floor class of a stored transition type; anything unmapped is returned verbatim. */
export function floorClass(value: string | undefined | null): FloorClass | undefined {
  if (!value) return undefined
  if (CODE_TYPES.includes(value)) return 'code'
  if (value === 'no_code' || value === 'documentation') return 'documentation'
  return value
}

/** Ladder rank: code 0, external_deploy 1, documentation 2. */
export const FLOOR_LADDER = ['code', 'external_deploy', 'documentation'] as const

export interface FloorView { cls: FloorClass | undefined; stored: string | undefined; showStored: boolean }

/** The floor is the governed `required_transition_type`; the legacy `transition_type` is the fallback. */
export function floorView(c: RegistryComponent): FloorView {
  const stored = c.required_transition_type ?? c.transition_type
  const cls = floorClass(stored)
  return { cls, stored, showStored: stored !== undefined && cls !== stored }
}

export function legacyDisagrees(c: RegistryComponent): boolean {
  if (!c.transition_type || !c.required_transition_type) return false
  return floorClass(c.transition_type) !== floorClass(c.required_transition_type)
}

export function isGoverned(status: string | undefined | null): boolean {
  return !!status && (GOVERNED_LIFECYCLE as readonly string[]).includes(status)
}

export type RegistrySegment = 'all' | 'pipeline' | 'production' | 'none' | 'legacy'

export function inSegment(c: RegistryComponent, seg: RegistrySegment): boolean {
  switch (seg) {
    case 'all': return true
    case 'pipeline': return (PIPELINE_STATUSES as readonly string[]).includes(c.lifecycle_status ?? '')
    case 'production': return c.lifecycle_status === 'production'
    case 'none': return !isGoverned(c.lifecycle_status)
    case 'legacy': return legacyDisagrees(c)
  }
}

/** Proposals are not registry components (forward-compatible with S82). */
export function registryRows(all: RegistryComponent[]): RegistryComponent[] {
  return all.filter((c) => c.record_kind !== 'proposal')
}

export function segmentCounts(rows: RegistryComponent[]): Record<RegistrySegment, number> {
  const out: Record<RegistrySegment, number> = { all: 0, pipeline: 0, production: 0, none: 0, legacy: 0 }
  for (const seg of Object.keys(out) as RegistrySegment[]) out[seg] = rows.filter((c) => inSegment(c, seg)).length
  return out
}

export function matchesText(c: RegistryComponent, q: string): boolean {
  const needle = q.trim().toLowerCase()
  if (!needle) return true
  return [c.component_id, c.component_name, c.project_id].some((v) => (v ?? '').toLowerCase().includes(needle))
}

export type SortField = 'component_id' | 'project_id' | 'category' | 'lifecycle_status' | 'updated_at'

export function sortRows(rows: RegistryComponent[], field: SortField, descending: boolean): RegistryComponent[] {
  const dir = descending ? -1 : 1
  return [...rows].sort((a, b) => {
    const av = (a[field] ?? '') as string
    const bv = (b[field] ?? '') as string
    return av < bv ? -dir : av > bv ? dir : a.component_id.localeCompare(b.component_id)
  })
}
