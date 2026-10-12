// DVP-TSK-974: pure helpers for the /recipes surface. Kit-free on purpose: router.tsx imports parseRecipesSearch
// statically, and the recipes/gates kits must stay in the lazy chunks.
import type { RecipeGetResult, RecipeVersion } from '@io-kit/recipes'

export const RECIPE_PROJECTS = ['enceladus', 'devops'] as const
export const DEFAULT_RECIPE_PROJECT = 'enceladus'
export const ACTIVE_RUN_STATUSES: readonly string[] = ['queued', 'running', 'awaiting_gate']

export interface RecipesSearch {
  project: string
}

/** ?project= is one of the served recipe projects; anything else falls back to enceladus. */
export function parseRecipesSearch(raw: Record<string, unknown>): RecipesSearch {
  const p = typeof raw.project === 'string' ? raw.project : ''
  return { project: (RECIPE_PROJECTS as readonly string[]).includes(p) ? p : DEFAULT_RECIPE_PROJECT }
}

/** The hub returns the resolved version either bare or wrapped as a RecipeRecord; accept both. */
export function versionOf(detail: Pick<RecipeGetResult, 'version'> | undefined): RecipeVersion | undefined {
  const v = detail?.version as unknown as (Partial<RecipeVersion> & { version?: unknown }) | null | undefined
  if (!v) return undefined
  if ('definition' in v && v.definition) return v as RecipeVersion
  const inner = v.version as RecipeVersion | undefined
  return inner && typeof inner === 'object' ? inner : undefined
}

export function schemaSummary(s: unknown): string {
  if (!s || typeof s !== 'object') return 'any'
  const n = s as Record<string, unknown>
  const parts: string[] = [Array.isArray(n.type) ? n.type.join('|') : typeof n.type === 'string' ? n.type : 'any']
  if (Array.isArray(n.enum)) parts.push(`enum(${n.enum.map(String).join('|')})`)
  if (typeof n.format === 'string') parts.push(`format ${n.format}`)
  if (typeof n.pattern === 'string') parts.push(`pattern ${n.pattern}`)
  if (n.default !== undefined) parts.push(`default ${JSON.stringify(n.default)}`)
  if (typeof n.description === 'string' && n.description) parts.push(n.description)
  return parts.join(' - ')
}

export interface InputRow {
  name: string
  required: boolean
  summary: string
}

export function inputRows(schema: Record<string, unknown> | undefined): InputRow[] {
  const props = (schema?.properties ?? {}) as Record<string, unknown>
  const req = new Set(Array.isArray(schema?.required) ? (schema?.required as string[]) : [])
  return Object.entries(props).map(([name, s]) => ({ name, required: req.has(name), summary: schemaSummary(s) }))
}

export const planHasUnresolved = (planned: unknown): boolean => JSON.stringify(planned ?? null).includes('$unresolved')

export const errMsg = (e: unknown): string => (e instanceof Error ? e.message : String(e))
