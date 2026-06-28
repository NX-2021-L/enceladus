/**
 * Normalized entity layer (ENC-TSK-B67 AC-12) — the cross-page consistency
 * mechanism.
 *
 * Architectural decision (AC-12, AC-24 #1): the v4 launch ships the **Zustand
 * normalized store** path rather than TanStack DB v0.6. Rationale committed to
 * the task worklog / PR body: TanStack DB was still beta (v0.6) at gamma; the
 * Zustand normalized store is production-stable, ~1KB, and gives fine-grained
 * selector-driven re-renders. TanStack DB remains the documented future upgrade
 * once it stabilizes (DOC-E470AC8CE9A8 §4.1/§9.2).
 *
 * Shape: `Record<EntityType, Record<ID, Entity>>`. A single `upsert(id, patch)`
 * from the WebSocket event handler propagates to every component subscribed via
 * a fine-grained `useEntity(type, id)` selector — detail page, embedded plan
 * badges, and feed — with no per-view manual cache walking (AC-6, AC-12).
 */

import { create } from 'zustand'

export type EntityType =
  | 'task'
  | 'issue'
  | 'feature'
  | 'plan'
  | 'lesson'
  | 'document'
  | 'record'

export interface NormalizedEntity {
  recordId: string
  record_type: EntityType | string
  [key: string]: unknown
}

type EntityTable = Record<string, NormalizedEntity>

interface EntityState {
  entities: Record<string, EntityTable>
  /** Insert or shallow-merge a single entity. */
  upsert: (type: string, id: string, patch: Partial<NormalizedEntity>) => void
  /** Bulk-load entities of a type (e.g. from a TanStack Query onSuccess). */
  hydrate: (type: string, list: NormalizedEntity[]) => void
  get: (type: string, id: string) => NormalizedEntity | undefined
  remove: (type: string, id: string) => void
  reset: () => void
}

export const useEntityStore = create<EntityState>((set, get) => ({
  entities: {},
  upsert: (type, id, patch) =>
    set((state) => {
      const table = state.entities[type] ?? {}
      const prev = table[id]
      const next: NormalizedEntity = {
        ...prev,
        ...patch,
        recordId: id,
        record_type: (patch.record_type as string) ?? prev?.record_type ?? type,
      }
      return { entities: { ...state.entities, [type]: { ...table, [id]: next } } }
    }),
  hydrate: (type, list) =>
    set((state) => {
      const table: EntityTable = { ...(state.entities[type] ?? {}) }
      for (const e of list) {
        const id = e.recordId
        if (!id) continue
        table[id] = { ...table[id], ...e, recordId: id }
      }
      return { entities: { ...state.entities, [type]: table } }
    }),
  get: (type, id) => get().entities[type]?.[id],
  remove: (type, id) =>
    set((state) => {
      const table = state.entities[type]
      if (!table || !(id in table)) return state
      const next = { ...table }
      delete next[id]
      return { entities: { ...state.entities, [type]: next } }
    }),
  reset: () => set({ entities: {} }),
}))

/**
 * Fine-grained selector hook. A component re-renders only when *its* entity
 * reference changes (AC-12 propagation, AC-16 minimal re-render).
 */
export function useEntity(type: string, id: string | undefined): NormalizedEntity | undefined {
  return useEntityStore((s) => (id ? s.entities[type]?.[id] : undefined))
}
