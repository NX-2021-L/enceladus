import { describe, expect, it, vi } from 'vitest'
import { installReauthFetch } from './reauthFetch'

const r = (status: number) => new Response('{}', { status })

describe('reauth fetch (ENC-ISS-546)', () => {
  it('refreshes once and retries a 401 API call', async () => {
    const base = vi.fn().mockResolvedValueOnce(r(401)).mockResolvedValueOnce(r(200))
    const refresh = vi.fn().mockResolvedValue(undefined)
    const res = await installReauthFetch({ refresh }, base)('/api/v1/projects')
    expect(res.status).toBe(200)
    expect(refresh).toHaveBeenCalledTimes(1)
    expect(base).toHaveBeenCalledTimes(2)
  })
  it('returns the 401 when refresh fails (kit redirects to sign-in)', async () => {
    const base = vi.fn().mockResolvedValue(r(401))
    const refresh = vi.fn().mockRejectedValue(new Error('AUTH_REFRESH_FAILED'))
    const res = await installReauthFetch({ refresh }, base)('/api/v1/projects')
    expect(res.status).toBe(401)
    expect(base).toHaveBeenCalledTimes(1)
  })
  it('never refreshes for auth routes or foreign origins', async () => {
    const base = vi.fn().mockResolvedValue(r(401))
    const refresh = vi.fn()
    const f = installReauthFetch({ refresh }, base)
    await f('/api/v1/auth/refresh')
    await f('https://example.com/api/v1/projects')
    expect(refresh).not.toHaveBeenCalled()
  })
})
