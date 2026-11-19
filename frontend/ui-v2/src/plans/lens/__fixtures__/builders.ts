/**
 * ENC-TSK-S98-0A (ENC-PLN-108 W3.1): builders for the golden fixtures of DOC-F3E7C341EB27 section 7.
 *
 * A fixture is plain data: the plan's ordered objectives, the corpus rows the page would hold, and the expected
 * resolution written out by hand. Nothing in a fixture is computed by the resolver, so a fixture diff is always a
 * deliberate act (section 6: bumping WAVE_RESOLVER_VERSION accompanies a grouping change).
 */
import type { ResolverRow } from '../types'
import type { WavePlacement } from '../resolveWaves'

/** A resolver row plus fields the resolver must IGNORE. `subtask_ids` is present on real records and wrong (F5). */
export type FixtureRow = ResolverRow & { subtask_ids?: readonly string[] }

export interface ExpectedWave {
  series: string | null
  number: number | null
  label: string
  parent_id: string | null
  placement: WavePlacement
  members: string[]
}

export interface GoldenFixture {
  id: `F${number}`
  plan_id: string
  /** The section 7 heading, for failure messages. */
  name: string
  /** Section 5.4 shape(s) pinned. */
  shape: string
  /** F11 only: no production record carried a wave_label on 2026-11-19 (spec section 2). */
  synthetic: boolean
  objectives: string[]
  rows: FixtureRow[]
  expected: {
    waves: ExpectedWave[]
    chips: string[]
    unassigned: string[]
    /**
     * Members placed by an objective's own title (step 3) or label (step 1), written out so the reason of each is asserted.
     * Every other member is a descendant placed by parent pointer.
     */
    byTitle: string[]
    byLabel: string[]
  }
}

export const task = (item_id: string, title: string, extra: Partial<FixtureRow> = {}): FixtureRow => ({
  item_id,
  record_type: 'task',
  title,
  status: 'open',
  ...extra,
})

export const feature = (item_id: string, title: string): FixtureRow => ({ item_id, record_type: 'feature', title, status: 'open' })

/** Child rows of `parent`, in the order given. Their titles are never parsed (spec section 4.2). */
export const kids = (parent: string, children: ReadonlyArray<readonly [id: string, title: string]>): FixtureRow[] =>
  children.map(([id, title]) => task(id, title, { parent }))
