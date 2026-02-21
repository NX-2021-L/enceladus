/**
 * useSessionLifecycle — Revalidates the auth session when the app resumes
 * after being idle (backgrounded, screen off, offline).
 *
 * On resume after 10+ minutes idle:
 *   1. Probes the session (GET request to a protected feed).
 *   2. If 401 → attempts silent credential refresh via /api/v1/auth/refresh.
 *   3. If refresh succeeds → retries probe, invalidates queries, resets auth.
 *   4. If refresh fails → transitions to 'logged-out' state.
 */

import { useEffect, useRef } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { isSessionExpiredError } from '../lib/authSession'
import { probeSession } from '../api/client'
import { refreshCredentials } from '../api/auth'
import { useAuthState } from '../lib/authState'

const IDLE_RESUME_MS = 10 * 60 * 1000
const RESUME_THROTTLE_MS = 15_000

export function useSessionLifecycle() {
  const queryClient = useQueryClient()
  const { authStatus, setAuthExpired, setLoggedOut, resetAuth, refreshSessionTimestamp } = useAuthState()
  const hiddenAtRef = useRef<number | null>(null)
  const lastResumeCheckRef = useRef(0)
  const inFlightRef = useRef(false)

  useEffect(() => {
    if (authStatus !== 'authenticated') return

    async function revalidateOnResume() {
      const now = Date.now()
      if (inFlightRef.current) return
      if (now - lastResumeCheckRef.current < RESUME_THROTTLE_MS) return
      lastResumeCheckRef.current = now
      inFlightRef.current = true

      try {
        await probeSession()
        refreshSessionTimestamp()
        await queryClient.invalidateQueries({ refetchType: 'active' })
      } catch (error) {
        if (isSessionExpiredError(error)) {
          // Try silent credential refresh before giving up
          setAuthExpired()
          const refreshed = await refreshCredentials()
          if (refreshed) {
            resetAuth()
            refreshSessionTimestamp()
            await queryClient.invalidateQueries({ refetchType: 'active' })
          } else {
            setLoggedOut()
          }
          return
        }
        // Non-auth error — just refresh queries
        await queryClient.invalidateQueries({ refetchType: 'active' })
      } finally {
        inFlightRef.current = false
      }
    }

    function onVisibilityChange() {
      if (document.visibilityState === 'hidden') {
        hiddenAtRef.current = Date.now()
        return
      }

      const hiddenAt = hiddenAtRef.current
      if (!hiddenAt) return
      if (Date.now() - hiddenAt < IDLE_RESUME_MS) return
      void revalidateOnResume()
    }

    function onFocus() {
      if (document.visibilityState !== 'visible') return
      const hiddenAt = hiddenAtRef.current
      if (!hiddenAt) return
      if (Date.now() - hiddenAt < IDLE_RESUME_MS) return
      void revalidateOnResume()
    }

    function onOnline() {
      if (document.visibilityState !== 'visible') return
      void revalidateOnResume()
    }

    window.addEventListener('focus', onFocus)
    window.addEventListener('online', onOnline)
    document.addEventListener('visibilitychange', onVisibilityChange)

    return () => {
      window.removeEventListener('focus', onFocus)
      window.removeEventListener('online', onOnline)
      document.removeEventListener('visibilitychange', onVisibilityChange)
    }
  }, [queryClient, authStatus, setAuthExpired, setLoggedOut, resetAuth, refreshSessionTimestamp])
}
