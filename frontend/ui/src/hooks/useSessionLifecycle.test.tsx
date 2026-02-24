import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { renderHook, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { SessionExpiredError } from '../lib/authSession'
import { useSessionLifecycle } from './useSessionLifecycle'

const { mockProbeSession, mockRefreshCredentials, mockUseAuthState } = vi.hoisted(() => ({
  mockProbeSession: vi.fn(),
  mockRefreshCredentials: vi.fn(),
  mockUseAuthState: vi.fn(),
}))

vi.mock('../api/client', () => ({
  probeSession: mockProbeSession,
}))

vi.mock('../api/auth', () => ({
  refreshCredentials: mockRefreshCredentials,
}))

vi.mock('../lib/authState', () => ({
  useAuthState: mockUseAuthState,
}))

function createWrapper(queryClient: QueryClient) {
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  )
}

describe('useSessionLifecycle', () => {
  let visibilityState: DocumentVisibilityState
  let nowMs: number
  let authState: {
    authStatus: 'authenticated'
    setAuthExpired: ReturnType<typeof vi.fn>
    setLoggedOut: ReturnType<typeof vi.fn>
    resetAuth: ReturnType<typeof vi.fn>
    refreshSessionTimestamp: ReturnType<typeof vi.fn>
  }

  function hideThenResumeAfterIdle() {
    visibilityState = 'hidden'
    document.dispatchEvent(new Event('visibilitychange'))
    nowMs += 10 * 60 * 1000 + 1
    visibilityState = 'visible'
    document.dispatchEvent(new Event('visibilitychange'))
  }

  beforeEach(() => {
    nowMs = Date.parse('2026-02-24T00:00:00Z')
    vi.spyOn(Date, 'now').mockImplementation(() => nowMs)
    visibilityState = 'visible'
    Object.defineProperty(document, 'visibilityState', {
      configurable: true,
      get: () => visibilityState,
    })

    authState = {
      authStatus: 'authenticated',
      setAuthExpired: vi.fn(),
      setLoggedOut: vi.fn(),
      resetAuth: vi.fn(),
      refreshSessionTimestamp: vi.fn(),
    }
    mockUseAuthState.mockReturnValue(authState)
    mockProbeSession.mockReset()
    mockRefreshCredentials.mockReset()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('revalidates and refreshes active queries on idle resume', async () => {
    mockProbeSession.mockResolvedValue(undefined)
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const invalidateSpy = vi
      .spyOn(queryClient, 'invalidateQueries')
      .mockResolvedValue(undefined as never)

    renderHook(() => useSessionLifecycle(), { wrapper: createWrapper(queryClient) })

    hideThenResumeAfterIdle()

    await waitFor(() => expect(mockProbeSession).toHaveBeenCalledTimes(1))
    expect(authState.refreshSessionTimestamp).toHaveBeenCalledTimes(1)
    expect(invalidateSpy).toHaveBeenCalledWith({ refetchType: 'active' })
  })

  it('attempts silent refresh on session expiry and resets auth when refresh succeeds', async () => {
    mockProbeSession.mockRejectedValue(new SessionExpiredError())
    mockRefreshCredentials.mockResolvedValue(true)
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    vi.spyOn(queryClient, 'invalidateQueries').mockResolvedValue(undefined as never)

    renderHook(() => useSessionLifecycle(), { wrapper: createWrapper(queryClient) })

    hideThenResumeAfterIdle()

    await waitFor(() => expect(authState.setAuthExpired).toHaveBeenCalledTimes(1))
    expect(mockRefreshCredentials).toHaveBeenCalledTimes(1)
    expect(authState.resetAuth).toHaveBeenCalledTimes(1)
    expect(authState.setLoggedOut).not.toHaveBeenCalled()
  })

  it('logs out when silent refresh fails after session expiry', async () => {
    mockProbeSession.mockRejectedValue(new SessionExpiredError())
    mockRefreshCredentials.mockResolvedValue(false)
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    vi.spyOn(queryClient, 'invalidateQueries').mockResolvedValue(undefined as never)

    renderHook(() => useSessionLifecycle(), { wrapper: createWrapper(queryClient) })

    hideThenResumeAfterIdle()

    await waitFor(() => expect(authState.setAuthExpired).toHaveBeenCalledTimes(1))
    expect(authState.setLoggedOut).toHaveBeenCalledTimes(1)
    expect(authState.resetAuth).not.toHaveBeenCalled()
  })
})
