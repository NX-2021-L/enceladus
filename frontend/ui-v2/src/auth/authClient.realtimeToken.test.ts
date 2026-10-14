import { beforeEach, describe, expect, it, vi } from 'vitest'

// DVP-TSK-928: AppSync Events needs the raw Cognito token, which the @io-kit/auth client never exposes. These
// tests pin how authClient.ts captures the id token from the adapter refresh and when it refreshes again.
const harness = vi.hoisted(() => {
  const state = {
    status: 'authenticated' as 'authenticated' | 'unauthenticated',
    adapterTokens: [] as string[],
    clientRefreshRunsAdapter: true,
    adapterRefresh: vi.fn(),
    clientRefresh: vi.fn(),
  }
  return state
})

vi.mock('@io-kit/auth', () => ({
  cognitoAdapter: () => ({
    kind: 'cognito',
    refresh: harness.adapterRefresh,
  }),
  createAuthClient: (config: { adapter: { refresh: () => Promise<unknown> } }) => ({
    ready: async () => ({ status: harness.status }),
    getSession: () => ({ status: harness.status }),
    refresh: harness.clientRefresh.mockImplementation(async () => {
      if (harness.clientRefreshRunsAdapter) await config.adapter.refresh()
    }),
  }),
}))

function jwt(expSeconds: number): string {
  return `h.${btoa(JSON.stringify({ exp: expSeconds })).replace(/=+$/, '')}.s`
}
const nowS = () => Math.floor(Date.now() / 1000)

async function load() {
  vi.resetModules()
  return import('./authClient')
}

describe('getRealtimeAuthToken', () => {
  beforeEach(() => {
    harness.status = 'authenticated'
    harness.clientRefreshRunsAdapter = true
    harness.adapterTokens = []
    harness.adapterRefresh.mockReset()
    harness.clientRefresh.mockClear()
    harness.adapterRefresh.mockImplementation(async () => {
      const token = harness.adapterTokens.shift() ?? jwt(nowS() + 3600)
      return { accessToken: token, idToken: token, exp: nowS() + 3600 }
    })
  })

  it('resolves null with no session, so the realtime client falls back to the API key', async () => {
    harness.status = 'unauthenticated'
    const { getRealtimeAuthToken } = await load()
    await expect(getRealtimeAuthToken()).resolves.toBeNull()
    expect(harness.clientRefresh).not.toHaveBeenCalled()
  })

  it('captures the id token from the locked client refresh and reuses it while it is fresh', async () => {
    const token = jwt(nowS() + 3600)
    harness.adapterTokens = [token]
    const { getRealtimeAuthToken } = await load()
    await expect(getRealtimeAuthToken()).resolves.toBe(token)
    await expect(getRealtimeAuthToken()).resolves.toBe(token)
    expect(harness.clientRefresh).toHaveBeenCalledTimes(1)
    expect(harness.adapterRefresh).toHaveBeenCalledTimes(1)
  })

  it('refreshes again once the captured token is inside the expiry skew', async () => {
    const nearlyExpired = jwt(nowS() + 30)
    const fresh = jwt(nowS() + 3600)
    harness.adapterTokens = [nearlyExpired, fresh]
    const { getRealtimeAuthToken } = await load()
    await expect(getRealtimeAuthToken()).resolves.toBe(fresh)
    expect(harness.adapterRefresh).toHaveBeenCalledTimes(2)
  })

  it('refreshes through the adapter directly when a peer tab refreshed and the client adopted its token', async () => {
    harness.clientRefreshRunsAdapter = false
    const token = jwt(nowS() + 3600)
    harness.adapterTokens = [token]
    const { getRealtimeAuthToken } = await load()
    await expect(getRealtimeAuthToken()).resolves.toBe(token)
    expect(harness.clientRefresh).toHaveBeenCalledTimes(1)
    expect(harness.adapterRefresh).toHaveBeenCalledTimes(1)
  })

  it('drops a captured token when the session ends', async () => {
    const { getRealtimeAuthToken } = await load()
    await getRealtimeAuthToken()
    harness.status = 'unauthenticated'
    await expect(getRealtimeAuthToken()).resolves.toBeNull()
    harness.status = 'authenticated'
    harness.adapterTokens = [jwt(nowS() + 3600)]
    await getRealtimeAuthToken()
    expect(harness.adapterRefresh).toHaveBeenCalledTimes(2)
  })
})
