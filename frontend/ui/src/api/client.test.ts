import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { SessionExpiredError } from '../lib/authSession'
import { fetchFeed, fetchWithAuth, probeSession } from './client'

describe('client api helpers', () => {
  const fetchMock = vi.fn()

  beforeEach(() => {
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('fetchWithAuth sets defaults and preserves explicit accept header', async () => {
    fetchMock.mockResolvedValue(new Response('{}', { status: 200 }))

    await fetchWithAuth('/mobile/v1/tasks.json', {
      headers: { accept: 'text/plain' },
      method: 'GET',
    })

    const [, init] = fetchMock.mock.calls[0] as [RequestInfo | URL, RequestInit]
    const headers = new Headers(init.headers)
    expect(headers.get('accept')).toBe('text/plain')
    expect(headers.get('x-requested-with')).toBe('XMLHttpRequest')
    expect(init.credentials).toBe('include')
    expect(init.cache).toBe('no-store')
  })

  it('fetchWithAuth throws SessionExpiredError on 401', async () => {
    fetchMock.mockResolvedValue(new Response('', { status: 401 }))
    await expect(fetchWithAuth('/x')).rejects.toBeInstanceOf(SessionExpiredError)
  })

  it('fetchFeed builds feed URL and returns parsed json', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ generated_at: '2026-02-24T00:00:00Z', tasks: [] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    const data = await fetchFeed<{ generated_at: string; tasks: unknown[] }>('tasks')
    expect(data.tasks).toEqual([])

    const [url] = fetchMock.mock.calls[0] as [string]
    expect(url).toBe('/mobile/v1/tasks.json')
  })

  it('probeSession throws when probe endpoint is non-2xx', async () => {
    fetchMock.mockResolvedValue(new Response('', { status: 503 }))
    await expect(probeSession()).rejects.toThrow('Session probe failed: 503')
    const [url] = fetchMock.mock.calls[0] as [string]
    expect(url.startsWith('/mobile/v1/projects.json?auth_probe=')).toBe(true)
  })
})
