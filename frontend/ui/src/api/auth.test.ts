import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { refreshCredentials } from './auth'

describe('refreshCredentials', () => {
  const fetchMock = vi.fn()

  beforeEach(() => {
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('returns true when refresh endpoint succeeds', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    await expect(refreshCredentials()).resolves.toBe(true)
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/auth/refresh',
      expect.objectContaining({
        method: 'POST',
        credentials: 'include',
        cache: 'no-store',
      }),
    )
  })

  it('returns false when endpoint responds non-2xx', async () => {
    fetchMock.mockResolvedValue(new Response('fail', { status: 500 }))
    await expect(refreshCredentials()).resolves.toBe(false)
  })

  it('returns false when fetch throws', async () => {
    fetchMock.mockRejectedValue(new Error('network'))
    await expect(refreshCredentials()).resolves.toBe(false)
  })
})
