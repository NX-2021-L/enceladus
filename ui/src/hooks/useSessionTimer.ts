/**
 * useSessionTimer — Client-side 60-minute session countdown.
 *
 * Polls localStorage every 15 seconds to check if the session has expired.
 * Refreshes the activity timestamp on:
 *   - React Router navigation (useLocation change)
 *   - User interaction (click, touchstart, keydown — debounced to 30s)
 *
 * When the session expires, transitions auth state to 'logged-out' without
 * waiting for a server response.
 */

import { useEffect, useRef } from 'react'
import { useLocation } from 'react-router-dom'
import { useAuthState } from '../lib/authState'

const SESSION_LS_KEY = 'enceladus:session_last_active'
const SESSION_DURATION_MS = 60 * 60 * 1000     // 60 minutes
const POLL_INTERVAL_MS = 15_000                 // check every 15s
const ACTIVITY_DEBOUNCE_MS = 30_000             // debounce user activity to 30s

export function useSessionTimer() {
  const { authStatus, setLoggedOut, refreshSessionTimestamp } = useAuthState()
  const lastActivityRefreshRef = useRef(0)
  const location = useLocation()

  // --- Refresh timestamp on navigation ---
  useEffect(() => {
    if (authStatus !== 'authenticated') return
    refreshSessionTimestamp()
  }, [location.pathname, authStatus, refreshSessionTimestamp])

  // --- Refresh timestamp on user interaction (debounced) ---
  useEffect(() => {
    if (authStatus !== 'authenticated') return

    function onActivity() {
      const now = Date.now()
      if (now - lastActivityRefreshRef.current < ACTIVITY_DEBOUNCE_MS) return
      lastActivityRefreshRef.current = now
      refreshSessionTimestamp()
    }

    window.addEventListener('click', onActivity, { passive: true })
    window.addEventListener('touchstart', onActivity, { passive: true })
    window.addEventListener('keydown', onActivity, { passive: true })

    return () => {
      window.removeEventListener('click', onActivity)
      window.removeEventListener('touchstart', onActivity)
      window.removeEventListener('keydown', onActivity)
    }
  }, [authStatus, refreshSessionTimestamp])

  // --- Poll for session expiry ---
  useEffect(() => {
    if (authStatus !== 'authenticated') return

    const timer = setInterval(() => {
      const lastActive = Number(localStorage.getItem(SESSION_LS_KEY) || '0')
      if (!lastActive || Date.now() - lastActive > SESSION_DURATION_MS) {
        setLoggedOut()
      }
    }, POLL_INTERVAL_MS)

    return () => clearInterval(timer)
  }, [authStatus, setLoggedOut])
}
