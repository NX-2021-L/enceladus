import { queryOptions } from '@tanstack/react-query'
import { fetchUserPreferences, SessionExpiredError } from './client'
import { readCachedPreferences, writeCachedPreferences } from './userPreferencesCache'
import type { UserPreferences } from '../types/userPreferences'

/** Stable key namespace for user preferences reads (ENC-TSK-L25). */
export const userPreferencesKeys = {
  all: ['userPreferences'] as const,
}

/**
 * Read-through: local cache paints instantly via `placeholderData`, then the
 * server response (canonical, cross-device) replaces it and is written back
 * to the cache. A session-expired/network failure leaves the last-known
 * local cache visible rather than blanking the UI.
 */
export const userPreferencesQueryOptions = () =>
  queryOptions({
    queryKey: userPreferencesKeys.all,
    queryFn: async ({ signal }): Promise<UserPreferences> => {
      const server = await fetchUserPreferences({ signal })
      writeCachedPreferences(server)
      return server
    },
    placeholderData: () => readCachedPreferences(),
    staleTime: 30_000,
    retry: (failureCount, error) => {
      if (error instanceof SessionExpiredError) return false
      return failureCount < 2
    },
  })
