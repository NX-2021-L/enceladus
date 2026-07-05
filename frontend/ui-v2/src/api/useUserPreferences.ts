import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { saveUserPreferences } from './client'
import { userPreferencesQueryOptions, userPreferencesKeys } from './userPreferencesQueryOptions'
import { writeCachedPreferences } from './userPreferencesCache'
import type { UserPreferences } from '../types/userPreferences'

/** Read the caller's preferences (local cache first, server canonical). */
export function useUserPreferences() {
  return useQuery(userPreferencesQueryOptions())
}

/**
 * Save preferences: optimistically updates the local cache + query cache
 * immediately (instant saved-search / recently-viewed UI feedback), then
 * confirms against the server. On failure, TanStack Query's invalidation on
 * next read reconciles against the server copy.
 */
export function useSaveUserPreferences() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (preferences: UserPreferences) => saveUserPreferences(preferences),
    onMutate: (preferences) => {
      writeCachedPreferences(preferences)
      queryClient.setQueryData(userPreferencesKeys.all, preferences)
    },
    onSuccess: (server) => {
      writeCachedPreferences(server)
      queryClient.setQueryData(userPreferencesKeys.all, server)
    },
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: userPreferencesKeys.all })
    },
  })
}
