/**
 * ENC-TSK-S98-0A (ENC-PLN-108 W3.1): shared types of the Plans lens.
 *
 * The lens is a set of pure functions with no I/O (DOC-5E1E205FA664 section 5.6). Nothing here imports the corpus or
 * the kit: the page maps an IndexRow into a LensRow, so the lens stays testable against plain objects and cannot
 * drift with the corpus adapter.
 */

/** One corpus row as the lens reads it. Every field but the identity is optional because the corpus carries them unevenly. */
export interface LensRow {
  item_id: string
  record_type: string
  title?: string | null
  project_id?: string | null
  status?: string | null
  /** ISO time. Orders plans (R5) and, when present, siblings inside a wave parent's tree (R-1). */
  created_at?: string | null
  /** The only source of membership below an objective (DOC-F3E7C341EB27 section 4.2). */
  parent?: string | null
  /** Authoritative wave when set (ruling D-20). Opaque: never parsed, compared byte for byte. */
  wave_label?: string | null
  /** Plan rows only, in order. */
  objectives_set?: readonly string[] | null
}

/**
 * What the resolver reads of a row (DOC-F3E7C341EB27 section 1). `subtask_ids` is deliberately not part of the contract:
 * it disagrees with `parent` in production (F5), so admitting it would make membership ambiguous.
 */
export type ResolverRow = Pick<LensRow, 'item_id' | 'record_type' | 'title' | 'parent' | 'wave_label' | 'status' | 'created_at'>

/** The plan a resolution is for: its ordered objectives. A full plan LensRow satisfies this. */
export interface ResolverPlan {
  objectives_set?: readonly string[] | null
}
