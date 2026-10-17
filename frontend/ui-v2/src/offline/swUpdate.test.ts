import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { APP_REFRESH_URL } from '../api/appRefresh'
import { REFRESH_FETCH_TIMEOUT_MS, REFRESH_STEP_TIMEOUT_MS, refreshApp } from './swUpdate'

/**
 * DVP-TSK-B42. "App refresh" is a deterministic reset, not an update attempt:
 * overlay -> server Clear-Site-Data call -> unregister service workers -> delete
 * caches -> clear web storage -> delete IndexedDB -> hard reload. The steps run
 * in that order on ONE press, and a throwing or hanging step must still end in
 * location.replace (this replaces the ENC-ISS-525 flaky skipWaiting path).
 */
describe('refreshApp (DVP-TSK-B42)', () => {
  const NOW = 1_760_000_000_000
  const replace = vi.fn()
  let order: string[]

  type Overrides = Partial<{
    fetch: () => Promise<unknown>
    getRegistrations: () => Promise<unknown[]>
    cachesKeys: () => Promise<string[]>
    localClear: () => void
    sessionClear: () => void
    databases: (() => Promise<{ name?: string }[]>) | undefined
  }>

  function install(o: Overrides = {}) {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string, init: RequestInit) => {
        order.push(`fetch:${url}:${init.cache}:${init.credentials}:overlay=${!!document.getElementById('ev2-refresh-overlay')}`)
        return o.fetch ? o.fetch() : { ok: true }
      }),
    )
    vi.stubGlobal('navigator', {
      serviceWorker: {
        getRegistrations:
          o.getRegistrations ??
          (async () => [
            { unregister: async () => (order.push('sw:unregister:1'), true) },
            { unregister: async () => (order.push('sw:unregister:2'), true) },
          ]),
      },
    })
    vi.stubGlobal('caches', {
      keys: o.cachesKeys ?? (async () => ['precache', 'runtime']),
      delete: vi.fn(async (k: string) => (order.push(`caches:delete:${k}`), true)),
    })
    vi.stubGlobal('localStorage', { clear: o.localClear ?? (() => order.push('localStorage.clear')) })
    vi.stubGlobal('sessionStorage', { clear: o.sessionClear ?? (() => order.push('sessionStorage.clear')) })
    const indexedDBStub: Record<string, unknown> = {
      deleteDatabase: vi.fn((name: string) => {
        order.push(`idb:delete:${name}`)
        const req: { onsuccess?: () => void; onerror?: () => void; onblocked?: () => void } = {}
        queueMicrotask(() => req.onsuccess?.())
        return req
      }),
    }
    if ('databases' in o) indexedDBStub.databases = o.databases
    else indexedDBStub.databases = async () => [{ name: 'workbox' }, { name: 'offline-queue' }, {}]
    vi.stubGlobal('indexedDB', indexedDBStub)
  }

  beforeEach(() => {
    order = []
    replace.mockReset()
    replace.mockImplementation((url: string) => order.push(`replace:${url}`))
    Object.defineProperty(window, 'location', { configurable: true, value: { replace } })
    vi.useFakeTimers()
    vi.setSystemTime(NOW)
    document.body.innerHTML = '<div id="root"></div>'
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
    document.body.innerHTML = ''
  })

  it('one press runs every step in order and ends in a cache-busting hard reload', async () => {
    install()
    const done = refreshApp()
    await vi.runAllTimersAsync()
    await done
    expect(order).toEqual([
      `fetch:${APP_REFRESH_URL}:no-store:include:overlay=true`,
      'sw:unregister:1',
      'sw:unregister:2',
      'caches:delete:precache',
      'caches:delete:runtime',
      'localStorage.clear',
      'sessionStorage.clear',
      'idb:delete:workbox',
      'idb:delete:offline-queue',
      `replace:/?_r=${NOW}`,
    ])
    expect(APP_REFRESH_URL).toBe('/api/v1/app/refresh')
    expect(replace).toHaveBeenCalledOnce()
  })

  it('shows the blocking Refreshing overlay synchronously and makes the app inert behind it', async () => {
    install({ fetch: () => new Promise(() => {}) })
    const done = refreshApp()
    // No awaiting: the overlay must already be on screen when the press handler returns.
    const overlay = document.getElementById('ev2-refresh-overlay')
    expect(overlay).not.toBeNull()
    expect(overlay?.textContent).toBe('Refreshing…')
    expect(overlay?.getAttribute('role')).toBe('alertdialog')
    expect(overlay?.getAttribute('aria-modal')).toBe('true')
    expect(document.getElementById('root')?.hasAttribute('inert')).toBe(true)
    expect(replace).not.toHaveBeenCalled()
    // Let the (hung-fetch) run finish so no run leaks into the next test.
    await vi.runAllTimersAsync()
    await done
    expect(replace).toHaveBeenCalledOnce()
  })

  it('a throwing step still reaches the hard reload, and the later steps still run', async () => {
    install({
      fetch: async () => {
        throw new TypeError('Failed to fetch')
      },
      getRegistrations: async () => {
        throw new Error('sw boom')
      },
      cachesKeys: async () => {
        throw new Error('caches boom')
      },
      localClear: () => {
        throw new Error('quota')
      },
      databases: async () => {
        throw new Error('idb boom')
      },
    })
    const done = refreshApp()
    await vi.runAllTimersAsync()
    await done
    // localStorage threw but sessionStorage.clear() still ran.
    expect(order).toContain('sessionStorage.clear')
    expect(order[order.length - 1]).toBe(`replace:/?_r=${NOW}`)
    expect(replace).toHaveBeenCalledOnce()
  })

  it('a hanging step cannot stall the reset past its timeout', async () => {
    const hang = () => new Promise<never>(() => {})
    install({ fetch: hang, getRegistrations: hang, cachesKeys: hang, databases: hang })
    const done = refreshApp()
    // Just under the sum of the per-step budgets: still waiting.
    const budget = REFRESH_FETCH_TIMEOUT_MS + 3 * REFRESH_STEP_TIMEOUT_MS
    await vi.advanceTimersByTimeAsync(budget - 100)
    expect(replace).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(REFRESH_STEP_TIMEOUT_MS + 200)
    await done
    expect(order).toContain('localStorage.clear')
    expect(order[order.length - 1]).toBe(`replace:/?_r=${NOW + budget}`)
    expect(replace).toHaveBeenCalledOnce()
  })

  it('skips IndexedDB cleanly when indexedDB.databases() is not available', async () => {
    install({ databases: undefined })
    const done = refreshApp()
    await vi.runAllTimersAsync()
    await done
    expect(order.some((s) => s.startsWith('idb:'))).toBe(false)
    expect(replace).toHaveBeenCalledOnce()
  })

  it('a second press while the reset runs shares it (one fetch, one reload)', async () => {
    install()
    const a = refreshApp()
    const b = refreshApp()
    await vi.runAllTimersAsync()
    await Promise.all([a, b])
    expect(order.filter((s) => s.startsWith('fetch:'))).toHaveLength(1)
    expect(replace).toHaveBeenCalledOnce()
    expect(document.querySelectorAll('#ev2-refresh-overlay')).toHaveLength(1)
  })
})
