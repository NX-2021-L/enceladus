import { afterEach, describe, expect, it, vi } from 'vitest'
import { WAVE_OVERRIDE_STORAGE_KEY, createWaveOverrideStore, deviceStorage } from './waveOverrides'
import type { WaveOverride } from './lens/waveState'

const memory = () => {
  const data = new Map<string, string>()
  return { data, getItem: (k: string) => data.get(k) ?? null, setItem: (k: string, v: string) => void data.set(k, v) }
}
const ov = (expanded: boolean, state: WaveOverride['state'] = 'todo', hot = false): WaveOverride => ({ expanded, state, hot })

afterEach(() => vi.restoreAllMocks())

describe('wave override store (ruling D-3: per device, until the wave changes)', () => {
  it('remembers a toggle on the device: a store built later over the same storage reads it back', () => {
    const storage = memory()
    createWaveOverrideStore(() => storage).set('P/W1', ov(true, 'active', true))
    expect(JSON.parse(storage.data.get(WAVE_OVERRIDE_STORAGE_KEY) as string)).toEqual({ 'P/W1': { expanded: true, state: 'active', hot: true } })
    expect(createWaveOverrideStore(() => storage).getSnapshot()).toEqual({ 'P/W1': { expanded: true, state: 'active', hot: true } })
  })

  it('returns the same snapshot object until something changes, and tells subscribers when it does', () => {
    const store = createWaveOverrideStore(() => memory())
    const a = store.getSnapshot()
    expect(store.getSnapshot()).toBe(a)
    const listener = vi.fn()
    const off = store.subscribe(listener)
    store.set('P/W1', ov(true))
    expect(listener).toHaveBeenCalledTimes(1)
    expect(store.getSnapshot()).not.toBe(a)
    off()
    store.set('P/W2', ov(false))
    expect(listener).toHaveBeenCalledTimes(1)
  })

  it('discards an override whose wave changed state, or hotness, and keeps the rest', () => {
    const store = createWaveOverrideStore(() => memory())
    store.set('P/stateChanged', ov(true, 'todo', false))
    store.set('P/hotChanged', ov(false, 'active', true))
    store.set('P/unchanged', ov(true, 'active', true))
    store.set('Q/notOnThePage', ov(true, 'done', false))
    store.reconcile({
      'P/stateChanged': { state: 'active', hot: false },
      'P/hotChanged': { state: 'active', hot: false },
      'P/unchanged': { state: 'active', hot: true },
    })
    expect(Object.keys(store.getSnapshot()).sort()).toEqual(['P/unchanged', 'Q/notOnThePage'])
  })

  it('persists the discard, so a wave that changes and changes back does not resurrect the old click', () => {
    const storage = memory()
    const store = createWaveOverrideStore(() => storage)
    store.set('P/W1', ov(true, 'todo', false))
    store.reconcile({ 'P/W1': { state: 'active', hot: true } })
    store.reconcile({ 'P/W1': { state: 'todo', hot: false } })
    expect(store.getSnapshot()).toEqual({})
    expect(JSON.parse(storage.data.get(WAVE_OVERRIDE_STORAGE_KEY) as string)).toEqual({})
    expect(createWaveOverrideStore(() => storage).getSnapshot()).toEqual({})
  })

  it('does not notify when a reconcile changes nothing', () => {
    const store = createWaveOverrideStore(() => memory())
    store.set('P/W1', ov(true, 'active', true))
    const listener = vi.fn()
    store.subscribe(listener)
    store.reconcile({ 'P/W1': { state: 'active', hot: true } })
    expect(listener).not.toHaveBeenCalled()
  })
})

describe('storage that is unavailable (private window, blocked, empty)', () => {
  it('works for the session in memory when every read and write throws', () => {
    const throwing = {
      getItem: () => {
        throw new Error('SecurityError')
      },
      setItem: () => {
        throw new Error('QuotaExceededError')
      },
    }
    const store = createWaveOverrideStore(() => throwing)
    expect(store.getSnapshot()).toEqual({})
    expect(() => store.set('P/W1', ov(true))).not.toThrow()
    expect(store.getSnapshot()).toEqual({ 'P/W1': ov(true) })
    expect(() => store.reconcile({ 'P/W1': { state: 'active', hot: false } })).not.toThrow()
    expect(store.getSnapshot()).toEqual({})
  })

  it('works when there is no storage at all', () => {
    const store = createWaveOverrideStore(() => null)
    store.set('P/W1', ov(true))
    expect(store.getSnapshot()).toEqual({ 'P/W1': ov(true) })
  })

  it('treats a blocked window.localStorage as no storage', () => {
    vi.spyOn(window, 'localStorage', 'get').mockImplementation(() => {
      throw new DOMException('denied', 'SecurityError')
    })
    expect(deviceStorage()).toBeNull()
    expect(() => createWaveOverrideStore().set('P/W1', ov(true))).not.toThrow()
  })

  it.each([
    ['corrupt JSON', '{not json'],
    ['an array', '[1,2]'],
    ['a string', '"x"'],
    ['null', 'null'],
    ['empty', ''],
  ])('starts empty from %s', (_name, raw) => {
    const storage = memory()
    storage.data.set(WAVE_OVERRIDE_STORAGE_KEY, raw)
    expect(createWaveOverrideStore(() => storage).getSnapshot()).toEqual({})
  })

  it('keeps well-formed entries and drops malformed ones', () => {
    const storage = memory()
    storage.data.set(
      WAVE_OVERRIDE_STORAGE_KEY,
      JSON.stringify({ ok: { expanded: true, state: 'active', hot: true }, noHot: { expanded: true, state: 'active' }, badState: { expanded: true, state: 'open', hot: false }, str: 'yes' }),
    )
    expect(createWaveOverrideStore(() => storage).getSnapshot()).toEqual({ ok: { expanded: true, state: 'active', hot: true } })
  })
})
