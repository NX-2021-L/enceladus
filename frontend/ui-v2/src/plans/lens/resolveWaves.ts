/**
 * ENC-TSK-S98-0A (ENC-PLN-108 W3.1): wave resolution, DOC-5E1E205FA664 section 5.4 as frozen by DOC-F3E7C341EB27
 * (resolver specification v1 and the eleven golden fixtures). Where the two differ, DOC-F3E7C341EB27 wins.
 *
 * A pure function of a plan's ordered objectives, the parent pointers, the wave labels and the titles. It reads no
 * clock and no service. It NEVER places a row by position (ruling D-20): a row reaches a wave by label, by parent
 * pointer or by a wave token in its own title, or it goes to Unassigned. "Nearest preceding wave" in step 3 selects
 * among waves of the same series and number; it is not adjacency, and an objective with no token is never attached to
 * the objective next to it.
 *
 * Every member and every unassigned row carries the reason it was placed, in `placements`, so a correct grouping
 * reached by the wrong route is observable and testable.
 */
import type { ResolverPlan, ResolverRow } from './types'

/** Bumping this is the explicit act that accompanies a grouping change (section 6, invariant 5). */
export const WAVE_RESOLVER_VERSION = 1 as const

/** Parent chains reach three levels below an objective in production (section 4.2), so the walk stops at three. */
export const MAX_DESCENDANT_DEPTH = 3

export type PlacementReason = 'label' | 'parent' | 'title' | 'unassigned'
/** How a wave came to exist; `unassigned` is a group, never a wave. */
export type WavePlacement = Exclude<PlacementReason, 'unassigned'>

export interface ResolvedWave {
  /** Unique inside one resolution. A repeated base key gets `#2`, `#3`, in objective order. */
  key: string
  /** `W` or `V` or the letter of a word form; null for an opaque label or an unnumbered wave parent. */
  series: string | null
  /** Null when the wave is labelled (labels are opaque) or has no token in its title. */
  number: number | null
  /** The wave's display label: its `wave_label`, else `<series><number>`, else its parent's id. */
  label: string
  parent_id: string | null
  /** The step that created the wave. Members that joined by another step are in `placements`. */
  placement: WavePlacement
  /** Task ids. The parent is excluded (it is `parent_id`). */
  members: string[]
}

export interface ResolvedPlan {
  resolver_version: typeof WAVE_RESOLVER_VERSION
  waves: ResolvedWave[]
  /** Non-task objectives, in objective order: chips on the plan header (D-7). */
  chips: string[]
  /** Childless task objectives with no label and no wave token; drawn after every wave (D-20). */
  unassigned: string[]
  /** Reason for every id in `waves[].members` and `unassigned`. */
  placements: Record<string, PlacementReason>
  /** Objectives with no row in the corpus, so their type is unknown. Never placed and never guessed. */
  missing: string[]
}

export interface WaveToken {
  series: string
  number: number
  /** What followed the number after a `.` or `-`: `W2.1b` -> `1b`, `W2-A` -> `A`. Orders members inside a wave only. */
  subordinal: string | null
  /** Where the token starts in the title. */
  index: number
}

// Alternative A: uppercase W or V, digits, preceded by start-of-string or a non-alphanumeric. Case-sensitive on purpose
// (`v1.1` in `DS v1.1 W1.1` is a version, not a wave).
const FORM_A = /(?<![A-Za-z0-9])([WV])(\d+)/
// Alternative B: the word `wave` in any case, optionally preceded by one uppercase letter as a separate token, then an
// optional space or hyphen, then digits. Explicit classes rather than the i flag so the series letter stays uppercase.
const FORM_B = /(?:(?<![A-Za-z0-9])([A-Z])\s+)?\b[Ww][Aa][Vv][Ee][\s-]?(\d+)/
const SUBORDINAL = /^[.-]([A-Za-z0-9]+)/

const subordinalAfter = (title: string, end: number): string | null => SUBORDINAL.exec(title.slice(end))?.[1] ?? null

/**
 * The wave token of a title: the FIRST match in reading order of either form (section 3.2). First-match is
 * load-bearing: wave-parent titles narrate their dependencies (`4.1 W1 ... depend on W0 only`).
 *
 * This is the only place a title is parsed, and the resolver calls it for objectives only, never for descendants
 * (section 4.2), which is what keeps `V1:`/`V2:` deliverable variants in HFY-PLN-004 from becoming phantom waves (F2).
 */
export function parseWaveToken(title: string | null | undefined): WaveToken | null {
  if (!title) return null
  const a = FORM_A.exec(title)
  const b = FORM_B.exec(title)
  const useA = a !== null && (b === null || a.index <= b.index)
  if (useA && a) {
    const number = Number.parseInt(a[2] ?? '', 10)
    return { series: a[1] ?? 'W', number, subordinal: subordinalAfter(title, a.index + a[0].length), index: a.index }
  }
  if (b) {
    const number = Number.parseInt(b[2] ?? '', 10)
    return { series: b[1] ?? 'W', number, subordinal: subordinalAfter(title, b.index + b[0].length), index: b.index }
  }
  return null
}

interface WaveBuilder {
  base: string
  series: string | null
  number: number | null
  label: string
  parent_id: string | null
  placement: WavePlacement
  /** Position of the founding objective in objectives_set: the ordering of last resort. */
  founder: number
  /** Parent-pointer members, in depth-first order. */
  descendants: string[]
  /** Label- and title-placed objectives, in objectives_set order. */
  objectives: string[]
}

const isTask = (row: ResolverRow): boolean => row.record_type.toLowerCase() === 'task'

const compareCreatedAt = (a: ResolverRow, b: ResolverRow): number => {
  const ta = a.created_at ? Date.parse(a.created_at) : Number.NaN
  const tb = b.created_at ? Date.parse(b.created_at) : Number.NaN
  const ha = !Number.isNaN(ta)
  const hb = !Number.isNaN(tb)
  if (ha && hb) return ta - tb
  if (ha) return -1
  if (hb) return 1
  return 0
}

/** Integer part numerically, then any trailing letters lexically: `1` < `1b` < `2` (spec decision R-1). */
const compareSubordinal = (a: string, b: string): number => {
  const pa = /^(\d*)(.*)$/.exec(a)
  const pb = /^(\d*)(.*)$/.exec(b)
  const na = pa?.[1] ? Number.parseInt(pa[1], 10) : -1
  const nb = pb?.[1] ? Number.parseInt(pb[1], 10) : -1
  if (na !== nb) return na - nb
  const ra = pa?.[2] ?? ''
  const rb = pb?.[2] ?? ''
  return ra < rb ? -1 : ra > rb ? 1 : 0
}

export function resolveWaves(plan: ResolverPlan, rows: readonly ResolverRow[]): ResolvedPlan {
  const byId = new Map<string, ResolverRow>()
  const children = new Map<string, ResolverRow[]>()
  for (const row of rows) {
    if (!byId.has(row.item_id)) byId.set(row.item_id, row)
    // Only tasks are tree members: task rows become timeline rows (section 1).
    if (row.parent && row.parent !== row.item_id && isTask(row)) {
      const siblings = children.get(row.parent)
      if (siblings) siblings.push(row)
      else children.set(row.parent, [row])
    }
  }
  // Siblings in created_at order when the rows carry it, otherwise in corpus order (stable sort).
  for (const siblings of children.values()) siblings.sort(compareCreatedAt)

  const objectives: string[] = []
  const seenObjective = new Set<string>()
  for (const id of plan.objectives_set ?? []) {
    if (typeof id !== 'string' || id === '' || seenObjective.has(id)) continue
    seenObjective.add(id)
    objectives.push(id)
  }

  const waves: WaveBuilder[] = []
  const byLabel = new Map<string, WaveBuilder>()
  const chips: string[] = []
  const unassigned: string[] = []
  const missing: string[] = []
  const reasons = new Map<string, PlacementReason>()
  const subordinals = new Map<string, string>()
  const visited = new Set<string>()

  /**
   * Descendants by parent pointer, depth-first, at most three levels below the objective it starts from. A cycle
   * terminates because every row is visited once. The walk does not cross into another objective of the same plan: that objective is placed by its own
   * rule and its subtree belongs to its own wave.
   */
  const walk = (id: string, depth: number, out: string[]): void => {
    if (depth > MAX_DESCENDANT_DEPTH) return
    for (const kid of children.get(id) ?? []) {
      if (visited.has(kid.item_id) || seenObjective.has(kid.item_id)) continue
      visited.add(kid.item_id)
      out.push(kid.item_id)
      reasons.set(kid.item_id, 'parent')
      walk(kid.item_id, depth + 1, out)
    }
  }

  const newWave = (init: Pick<WaveBuilder, 'base' | 'series' | 'number' | 'label' | 'placement' | 'parent_id'>, founder: number): WaveBuilder => {
    const wave: WaveBuilder = { ...init, founder, descendants: [], objectives: [] }
    waves.push(wave)
    return wave
  }

  objectives.forEach((id, index) => {
    const row = byId.get(id)
    if (!row) {
      missing.push(id)
      return
    }
    // Step 6: objectives that are not tasks are chips on the plan header (D-7), whatever else they carry.
    if (!isTask(row)) {
      chips.push(id)
      return
    }
    const token = parseWaveToken(row.title)
    if (token?.subordinal) subordinals.set(id, token.subordinal)
    const kids = children.get(id) ?? []
    const label = row.wave_label ? row.wave_label : null

    // Step 1: a labelled objective belongs to the wave of its label; with children it is that wave's parent.
    if (label !== null) {
      let wave = byLabel.get(label)
      if (!wave) {
        wave = newWave({ base: `label:${label}`, series: null, number: null, label, placement: 'label', parent_id: null }, index)
        byLabel.set(label, wave)
      }
      if (kids.length > 0 && wave.parent_id === null) {
        wave.parent_id = id
      } else {
        wave.objectives.push(id)
        reasons.set(id, 'label')
      }
      if (kids.length > 0) walk(id, 1, wave.descendants)
      return
    }

    // Step 2: an objective with children is a wave of its own. Waves are never merged by number here.
    if (kids.length > 0) {
      const wave = newWave(
        token
          ? { base: `${token.series}${token.number}`, series: token.series, number: token.number, label: `${token.series}${token.number}`, placement: 'parent', parent_id: id }
          : { base: id, series: null, number: null, label: id, placement: 'parent', parent_id: id },
        index,
      )
      walk(id, 1, wave.descendants)
      return
    }

    // Step 3: a childless, unlabelled task whose title names a wave joins the nearest preceding wave of that series and
    // number, or founds a parentless wave. Series and number must both match: `H wave 0` is not `F wave 0`.
    if (token) {
      let target: WaveBuilder | undefined
      for (let i = waves.length - 1; i >= 0; i -= 1) {
        const w = waves[i]
        if (w && w.series === token.series && w.number === token.number) {
          target = w
          break
        }
      }
      target ??= newWave(
        { base: `${token.series}${token.number}`, series: token.series, number: token.number, label: `${token.series}${token.number}`, placement: 'title', parent_id: null },
        index,
      )
      target.objectives.push(id)
      reasons.set(id, 'title')
      return
    }

    // Step 4: everything else is Unassigned. Never attached to a neighbour (D-20).
    unassigned.push(id)
    reasons.set(id, 'unassigned')
  })

  // Step 5: by number when every wave is numbered in one series, otherwise by objective order.
  const numbered = waves.length > 0 && waves.every((w) => w.number !== null) && new Set(waves.map((w) => w.series)).size === 1
  const ordered = [...waves].sort((a, b) => (numbered && a.number !== b.number ? (a.number as number) - (b.number as number) : a.founder - b.founder))

  const keySeen = new Map<string, number>()
  // Keys are assigned in founding order so `#2` always means the later wave, whichever way the waves are then sorted.
  const keyOf = new Map<WaveBuilder, string>()
  for (const w of waves) {
    const n = (keySeen.get(w.base) ?? 0) + 1
    keySeen.set(w.base, n)
    keyOf.set(w, n === 1 ? w.base : `${w.base}#${n}`)
  }

  const resolved: ResolvedWave[] = ordered.map((w) => {
    let members = [...w.descendants, ...w.objectives]
    // Within a wave: by subordinal when EVERY member has one (descendant titles are never parsed, so a wave parent's
    // tree never qualifies); otherwise in assembled order, which is corpus order (decision R-1).
    if (members.length > 1 && members.every((m) => subordinals.has(m))) {
      members = members
        .map((m, i) => ({ m, i }))
        .sort((x, y) => compareSubordinal(subordinals.get(x.m) as string, subordinals.get(y.m) as string) || x.i - y.i)
        .map((x) => x.m)
    }
    return {
      key: keyOf.get(w) as string,
      series: w.series,
      number: w.number,
      label: w.label,
      parent_id: w.parent_id,
      placement: w.placement,
      members,
    }
  })

  const placements: Record<string, PlacementReason> = {}
  for (const w of resolved) for (const m of w.members) placements[m] = reasons.get(m) as PlacementReason
  for (const u of unassigned) placements[u] = 'unassigned'

  return { resolver_version: WAVE_RESOLVER_VERSION, waves: resolved, chips, unassigned, placements, missing }
}
