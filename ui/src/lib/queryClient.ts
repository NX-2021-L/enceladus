import { QueryCache, MutationCache, QueryClient } from '@tanstack/react-query'
import { isSessionExpiredError } from './authSession'
import { isMutationRetryExhaustedError } from '../api/mutations'

// Module-level callbacks registered by AppShell via registerSessionExpiredHandler
// and registerLoggedOutHandler. Called whenever auth-related errors are detected
// so the UI can show the appropriate overlay/screen.
let _onSessionExpired: (() => void) | null = null
let _onLoggedOut: (() => void) | null = null

export function registerSessionExpiredHandler(handler: () => void): void {
  _onSessionExpired = handler
}

export function registerLoggedOutHandler(handler: () => void): void {
  _onLoggedOut = handler
}

const queryCache = new QueryCache({
  onError: (error, query) => {
    if (!isSessionExpiredError(error)) return
    // Queries with suppressSessionExpired meta (e.g. live feed polling)
    // should silently fail and retry on the next poll cycle instead of
    // flashing the SessionExpiredOverlay every 3 seconds.
    if (query.meta?.suppressSessionExpired) return
    _onSessionExpired?.()
  },
})

const mutationCache = new MutationCache({
  onError: (error) => {
    // Only force logged-out when credential refresh definitively failed.
    // Other exhausted mutation errors (e.g. backend regression) should stay
    // in-app and surface debug details on the page.
    if (isMutationRetryExhaustedError(error)) {
      if (error.message.includes('Credential refresh failed')) {
        _onLoggedOut?.()
      }
    }
  },
})

function shouldRetry(failureCount: number, error: unknown): boolean {
  if (isSessionExpiredError(error)) return false
  return failureCount < 2
}

export const queryClient = new QueryClient({
  queryCache,
  mutationCache,
  defaultOptions: {
    queries: {
      staleTime: 2 * 60 * 1000,
      gcTime: 30 * 60 * 1000,
      retry: shouldRetry,
      refetchOnWindowFocus: true,
      refetchOnReconnect: true,
    },
  },
})
