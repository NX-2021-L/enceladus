import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { queryClient } from '../api/queryClient'
import { CLEANUP_TIMEOUT_MS, LOGOUT_URL, performLogout } from './logout'

/**
 * DVP-TSK-B41. performLogout() used to fire a never-awaited POST at a route
 * that 404ed and navigate at once, so the HttpOnly refresh cookie survived and
 * the app signed back in on reload. The contract now: the server logout is
 * AWAITED, client state is cleared after it, and navigation is the LAST step --
 * but it always happens, whatever fails or hangs before it.
 */
describe('performLogout (DVP-TSK-B41)', () => {
  const replace = vi.fn()
  let order: string[]

  function jsonResponse(body: unknown, ok = true): Response {
    return { ok, status: ok ? 200 : 403, json: async () => body } as unknown as Response
  }

  function stubBrowser(opts: {
    fetchImpl: (url: string, init: RequestInit) => Promise<Response>
    unregister?: () => Promise<unknown>
    cachesKeys?: () => Promise<string[]>
  }) {
    const fetchMock = vi.fn(async (url: string, init: RequestInit) => {
      order.push('fetch:start')
      try {
        return await opts.fetchImpl(url, init)
      } finally {
        order.push('fetch:settled')
      }
    })
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('caches', {
      keys: opts.cachesKeys ?? (async () => ['workbox-precache']),
      delete: vi.fn(async () => {
        order.push('caches:delete')
        return true
      }),
    })
    vi.stubGlobal('navigator', {
      serviceWorker: {
        getRegistrations: async () => [
          {
            unregister:
              opts.unregister ??
              (async () => {
                order.push('sw:unregister')
                return true
              }),
          },
        ],
      },
    })
    return fetchMock
  }

  beforeEach(() => {
    order = []
    replace.mockReset()
    replace.mockImplementation(() => order.push('navigate'))
    Object.defineProperty(window, 'location', { configurable: true, value: { replace, assign: vi.fn() } })
    localStorage.setItem('enceladus:session_last_active', '1')
    sessionStorage.setItem('k', 'v')
    vi.spyOn(queryClient, 'clear').mockImplementation(() => order.push('queryClient.clear'))
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  it('posts the logout with credentials, keepalive and the io-kit CSRF header', async () => {
    const fetchMock = stubBrowser({ fetchImpl: async () => jsonResponse({ logged_out: true, logout_url: null }) })
    await performLogout()
    expect(fetchMock).toHaveBeenCalledOnce()
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe(LOGOUT_URL)
    expect(LOGOUT_URL).toBe('/api/v1/auth/logout')
    expect(init).toMatchObject({
      method: 'POST',
      credentials: 'include',
      keepalive: true,
      headers: { 'X-Requested-With': 'io-kit' },
    })
  })

  it('does not navigate until the logout request has settled, then navigates last', async () => {
    let release!: (r: Response) => void
    stubBrowser({ fetchImpl: () => new Promise<Response>((res) => (release = res)) })

    const done = performLogout()
    await vi.waitFor(() => expect(order).toContain('fetch:start'))
    // Request in flight: nothing cleared, no navigation.
    await new Promise((r) => setTimeout(r, 30))
    expect(replace).not.toHaveBeenCalled()
    expect(queryClient.clear).not.toHaveBeenCalled()
    expect(localStorage.getItem('enceladus:session_last_active')).toBe('1')

    release(jsonResponse({ logged_out: true, logout_url: 'https://auth.example.net/logout?client_id=c&logout_uri=https%3A%2F%2Fapp%2F' }))
    await done

    expect(replace).toHaveBeenCalledOnce()
    expect(replace).toHaveBeenCalledWith('https://auth.example.net/logout?client_id=c&logout_uri=https%3A%2F%2Fapp%2F')
    expect(order.indexOf('fetch:settled')).toBeLessThan(order.indexOf('queryClient.clear'))
    expect(order.indexOf('queryClient.clear')).toBeLessThan(order.indexOf('sw:unregister'))
    expect(order.indexOf('sw:unregister')).toBeLessThan(order.indexOf('navigate'))
    expect(order.indexOf('caches:delete')).toBeLessThan(order.indexOf('navigate'))
    expect(order[order.length - 1]).toBe('navigate')
    expect(localStorage.getItem('enceladus:session_last_active')).toBeNull()
    expect(sessionStorage.getItem('k')).toBeNull()
  })

  it('goes to / when the server returns a null logout_url', async () => {
    stubBrowser({ fetchImpl: async () => jsonResponse({ logged_out: true, logout_url: null }) })
    await performLogout()
    expect(replace).toHaveBeenCalledWith('/')
  })

  it.each([
    ['javascript: URL', 'javascript:alert(1)'],
    ['http URL', 'http://auth.example.net/logout'],
    ['garbage', 'not a url'],
  ])('ignores an unsafe logout_url (%s)', async (_label, logout_url) => {
    stubBrowser({ fetchImpl: async () => jsonResponse({ logged_out: true, logout_url }) })
    await performLogout()
    expect(replace).toHaveBeenCalledWith('/')
  })

  it('tolerates a network failure: still clears state and navigates to /', async () => {
    stubBrowser({ fetchImpl: async () => Promise.reject(new TypeError('Failed to fetch')) })
    await performLogout()
    expect(queryClient.clear).toHaveBeenCalled()
    expect(replace).toHaveBeenCalledWith('/')
  })

  it('tolerates an HTTP error response (403 CSRF / 5xx): navigates to /', async () => {
    stubBrowser({ fetchImpl: async () => jsonResponse({ code: 'AUTH_FORBIDDEN' }, false) })
    await performLogout()
    expect(replace).toHaveBeenCalledWith('/')
  })

  it('a hanging service-worker teardown cannot block navigation past the cleanup timeout', async () => {
    vi.useFakeTimers()
    stubBrowser({
      fetchImpl: async () => jsonResponse({ logged_out: true, logout_url: null }),
      unregister: () => new Promise(() => {}),
    })
    const done = performLogout()
    await vi.advanceTimersByTimeAsync(CLEANUP_TIMEOUT_MS - 100)
    expect(replace).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(200)
    await done
    expect(replace).toHaveBeenCalledWith('/')
  })

  it('a throwing caches.keys() does not stop the service worker teardown or the navigation', async () => {
    stubBrowser({
      fetchImpl: async () => jsonResponse({ logged_out: true, logout_url: null }),
      cachesKeys: async () => {
        throw new Error('boom')
      },
    })
    await performLogout()
    expect(order).toContain('sw:unregister')
    expect(replace).toHaveBeenCalledWith('/')
  })

  it('a second press while the first is running shares the run (one request, one navigation)', async () => {
    let release!: (r: Response) => void
    const fetchMock = stubBrowser({ fetchImpl: () => new Promise<Response>((res) => (release = res)) })
    const a = performLogout()
    const b = performLogout()
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalled())
    release(jsonResponse({ logged_out: true, logout_url: null }))
    await Promise.all([a, b])
    expect(fetchMock).toHaveBeenCalledOnce()
    expect(replace).toHaveBeenCalledOnce()
  })
})
