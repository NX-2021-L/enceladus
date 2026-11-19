/**
 * ENC-TSK-S98-0B (ENC-PLN-108 W3.2): manual wave toggles, remembered per device (ruling D-3).
 *
 * A toggle is a `WaveOverride` from the lens: the expansion the user chose plus the state and hotness of the wave when they
 * chose it. `shown()` in the lens already ignores an override whose state or hotness no longer matches, so the automatic
 * behaviour fires on a real transition. This store adds the two things the lens cannot do: keep the choice on the device
 * between visits, and DISCARD an override once its wave has changed, so a wave that goes todo to active and back to todo
 * does not resurrect a click made long before.
 *
 * Storage is `localStorage`, one JSON object under one key. Every read and write is inside try/catch: it throws in a
 * private window, can be blocked, and can come back empty. When it is unavailable the store still works for the session
 * in memory and the page renders the same, so persistence is a convenience and never a precondition.
 */
import { useSyncExternalStore } from 'react'
import type { WaveOverride, WaveState } from './lens/waveState'

export const WAVE_OVERRIDE_STORAGE_KEY = 'enc.plans.waveOverrides.v1'

export type WaveOverrideMap = Readonly<Record<string, WaveOverride>>

type StorageLike = Pick<Storage, 'getItem' | 'setItem'>

const STATES: readonly WaveState[] = ['todo', 'active', 'done']

const isOverride = (v: unknown): v is WaveOverride => {
  if (typeof v !== 'object' || v === null) return false
  const o = v as Record<string, unknown>
  return typeof o.expanded === 'boolean' && typeof o.hot === 'boolean' && typeof o.state === 'string' && (STATES as readonly string[]).includes(o.state)
}

/** `window.localStorage`, or null when even touching it throws (a SecurityError in a blocked context). */
export function deviceStorage(): StorageLike | null {
  try {
    return typeof window === 'undefined' ? null : window.localStorage
  } catch {
    return null
  }
}

export interface WaveOverrideStore {
  /** The current overrides. The same object until something changes, as useSyncExternalStore requires. */
  getSnapshot: () => WaveOverrideMap
  subscribe: (listener: () => void) => () => void
  /** Remembers a toggle under a wave key (`<plan id>/<wave key>`). */
  set: (key: string, override: WaveOverride) => void
  /**
   * Drops every override whose wave is present in `current` with a different state or hotness. Waves not listed are left
   * alone: a plan scrolled out of the page keeps its choice until it is seen to change.
   */
  reconcile: (current: Readonly<Record<string, { state: WaveState; hot: boolean }>>) => void
}

export function createWaveOverrideStore(getStorage: () => StorageLike | null = deviceStorage): WaveOverrideStore {
  const read = (): Record<string, WaveOverride> => {
    try {
      const raw = getStorage()?.getItem(WAVE_OVERRIDE_STORAGE_KEY)
      if (!raw) return {}
      const parsed: unknown = JSON.parse(raw)
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return {}
      const out: Record<string, WaveOverride> = {}
      for (const [k, v] of Object.entries(parsed)) if (isOverride(v)) out[k] = { expanded: v.expanded, state: v.state, hot: v.hot }
      return out
    } catch {
      return {}
    }
  }
  const write = (map: WaveOverrideMap): void => {
    try {
      getStorage()?.setItem(WAVE_OVERRIDE_STORAGE_KEY, JSON.stringify(map))
    } catch {
      // Private window, quota or blocked storage: the choice lives for this session in memory only.
    }
  }

  let snapshot: WaveOverrideMap | null = null
  const listeners = new Set<() => void>()
  const current = (): WaveOverrideMap => (snapshot ??= read())
  const commit = (next: WaveOverrideMap): void => {
    snapshot = next
    write(next)
    for (const l of [...listeners]) l()
  }

  return {
    getSnapshot: current,
    subscribe: (listener) => {
      listeners.add(listener)
      return () => {
        listeners.delete(listener)
      }
    },
    set: (key, override) => {
      commit({ ...current(), [key]: override })
    },
    reconcile: (live) => {
      const now = current()
      const kept: Record<string, WaveOverride> = {}
      let dropped = false
      for (const [key, o] of Object.entries(now)) {
        const w = live[key]
        if (w && (w.state !== o.state || w.hot !== o.hot)) dropped = true
        else kept[key] = o
      }
      if (dropped) commit(kept)
    },
  }
}

let deviceStore: WaveOverrideStore | undefined
/** The one store of this device's page; created on first use so importing the module touches no storage. */
export const getDeviceWaveOverrideStore = (): WaveOverrideStore => (deviceStore ??= createWaveOverrideStore())

export function useWaveOverrides(store: WaveOverrideStore): WaveOverrideMap {
  return useSyncExternalStore(store.subscribe, store.getSnapshot, store.getSnapshot)
}
