/**
 * Status role lookup (ENC-TSK-S60-0B, ENC-PLN-106; Design System v1.1 spec DOC-8253497AC9FC
 * sections 4.1 to 4.4).
 *
 * One lookup for what a status means, read from data: frontend/design-system-2/status-map.json.
 * A status string and its record kind go in; one of nine roles comes out. The pill and the
 * feed rail both read the role, so they cannot disagree.
 *
 * Priority, severity, record type and checkout are never inputs to the role. Record type is an
 * input to the rail only, as its default when the role has no rail of its own.
 *
 * Lookup order (spec 4.2), after trimming and lowercasing:
 *   1. kinds[kind].statuses[status]
 *   2. the same table with hyphens and underscores swapped. The feed delivers some task
 *      statuses with underscores (in_progress, merged_main, deploy_success) while the governed
 *      vocabulary uses hyphens (baseline DOC-9DBB9BA1DFA3 finding 1). The swap stays inside one
 *      kind's table, so it cannot borrow a meaning from another kind.
 *   3. any[status]
 *   4. legacy[status]
 *   5. unknown
 * A string that differs by kind (approved, deployed, pending) with no kind given takes the
 * first role the map lists for it.
 */
import statusMap from '../../../design-system-2/status-map.json'

export const STATUS_ROLES = [
  'todo',
  'active',
  'caution',
  'waiting',
  'done',
  'live',
  'failed',
  'retired',
  'unknown',
] as const

export type StatusRole = (typeof STATUS_ROLES)[number]

type KindTable = { statuses: Record<string, string> }
type RoleDef = { rail_token: string | null; cue: { glyph: string } }

const kinds = statusMap.kinds as unknown as Record<string, KindTable>
const anyTable = statusMap.any as Record<string, string>
const legacy = statusMap.legacy as Record<string, string>
const ambiguous = statusMap.ambiguous_without_kind as Record<string, string[]>
const roles = statusMap.roles as unknown as Record<StatusRole, RoleDef>
const rail = statusMap.dimensions.left_rail as {
  by_record_type: Record<string, string>
  by_role_override: Record<string, string>
}

export const STATUS_MAP_VERSION: string = statusMap.version

const isRole = (v: unknown): v is StatusRole => typeof v === 'string' && (STATUS_ROLES as readonly string[]).includes(v)

/** Record kinds as the app names them, mapped to the status-map kind keys. */
const KIND_ALIASES: Record<string, string> = {
  coordination: 'coordination_request',
  'coordination-request': 'coordination_request',
  request: 'coordination_request',
  session: 'agent_session',
  'agent-session': 'agent_session',
  'lesson-candidate': 'lesson_candidate',
  'deployment-decision': 'deployment_decision',
  'recipe-run': 'recipe_run',
  'recipe-step': 'recipe_step',
  'gate-verdict': 'gate_verdict',
  'search-signal': 'search_signal',
}

export function normalizeKind(kind: string | null | undefined): string | undefined {
  const k = kind?.trim().toLowerCase()
  if (!k) return undefined
  if (k in kinds) return k
  return KIND_ALIASES[k] ?? KIND_ALIASES[k.replace(/_/g, '-')]
}

const swapSeparators = (s: string) =>
  s.includes('_') ? s.replace(/_/g, '-') : s.includes('-') ? s.replace(/-/g, '_') : undefined

/** The role a status has for a record kind. Never throws; anything unmapped is 'unknown'. */
export function statusRole(kind: string | null | undefined, status: string | null | undefined): StatusRole {
  const s = status?.trim().toLowerCase()
  if (!s) return 'unknown'
  const k = normalizeKind(kind)
  const table = k ? kinds[k]?.statuses : undefined
  if (table) {
    const direct = table[s]
    if (isRole(direct)) return direct
    const swapped = swapSeparators(s)
    const alt = swapped ? table[swapped] : undefined
    if (isRole(alt)) return alt
  } else {
    const amb = ambiguous[s]?.[0]
    if (isRole(amb)) return amb
  }
  const fromAny = anyTable[s]
  if (isRole(fromAny)) return fromAny
  const fromLegacy = legacy[s]
  if (isRole(fromLegacy)) return fromLegacy
  return 'unknown'
}

/** Pill label: the status string with hyphens and underscores shown as spaces (CSS uppercases it). */
export function statusLabel(status: string | null | undefined): string {
  return (status ?? '').trim().replace(/[-_]+/g, ' ')
}

/** The glyph name a role carries (ring, play, return, pause, check, disc, cross, dash, diamond). */
export function roleGlyph(role: StatusRole): string {
  return roles[role]?.cue.glyph ?? 'diamond'
}

/**
 * The rail token for a feed row (spec 4.4): the role's own rail when it has one (caution,
 * waiting, failed), otherwise the record type's rail. Returns a custom property name without
 * the leading dashes, e.g. 'rail-plan' or 'status-waiting-rail'.
 */
export function railToken(recordType: string | null | undefined, role: StatusRole): string {
  const override = rail.by_role_override[role]
  if (override) return override
  const t = recordType?.trim().toLowerCase() ?? ''
  return rail.by_record_type[t] ?? rail.by_record_type['*'] ?? 'rail-default'
}

/** Whether the role overrides the type rail (the row then carries data-rail=<role>). */
export function railOverrides(role: StatusRole): boolean {
  return Boolean(rail.by_role_override[role])
}

/** Every kind the map knows, for tests and diagnostics. */
export function mappedKinds(): string[] {
  return Object.keys(kinds)
}

/** Every status the map lists for a kind, with its role. */
export function kindStatuses(kind: string): Record<string, StatusRole> {
  const table = kinds[kind]?.statuses ?? {}
  return Object.fromEntries(Object.entries(table).filter(([, r]) => isRole(r))) as Record<string, StatusRole>
}
