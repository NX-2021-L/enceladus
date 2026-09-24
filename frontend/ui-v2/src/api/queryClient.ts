import { QueryClient } from '@tanstack/react-query'
import { SessionExpiredError } from './client'

/**
 * The single QueryClient. Route loaders (`ensureQueryData`) and route
 * components (`useSuspenseQuery`) share this instance so a loader-primed cache
 * entry is what the component suspends on — no double fetch, no loading flash.
 */
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 2 * 60 * 1000,
      gcTime: 30 * 60 * 1000,
      refetchOnWindowFocus: false,
      retry: (failureCount, error) => {
        // Never retry an expired session — surfacing re-auth is the caller's job.
        if (error instanceof SessionExpiredError) return false
        return failureCount < 2
      },
    },
  },
})
