import { createContext, useContext, useState, useCallback, useRef } from 'react'
import type { ReactNode } from 'react'
import { performLogout } from './logout'

const SESSION_LS_KEY = 'enceladus:session_last_active'
const SESSION_DURATION_MS = 60 * 60 * 1000 // 60 minutes

export type AuthStatus = 'authenticated' | 'expired' | 'logged-out'

interface AuthState {
  authStatus: AuthStatus
  /** Epoch ms when the current session expires (null if no session) */
  sessionExpiresAt: number | null
  /** Transition to 'expired' — triggers SessionExpiredOverlay (refresh attempt) */
  setAuthExpired: () => void
  /** Transition to 'logged-out' — triggers LoggedOutScreen */
  setLoggedOut: () => void
  /** Transition back to 'authenticated' — dismiss overlay after successful refresh */
  resetAuth: () => void
  /** Update the session activity timestamp (call on action/navigation) */
  refreshSessionTimestamp: () => void
}

const AuthStateContext = createContext<AuthState>({
  authStatus: 'authenticated',
  sessionExpiresAt: null,
  setAuthExpired: () => {},
  setLoggedOut: () => {},
  resetAuth: () => {},
  refreshSessionTimestamp: () => {},
})

export function AuthStateProvider({ children }: { children: ReactNode }) {
  const [authStatus, setAuthStatus] = useState<AuthStatus>(() => {
    // On initial load, check if we have an active session
    const lastActive = Number(localStorage.getItem(SESSION_LS_KEY) || '0')
    if (!lastActive) return 'logged-out'
    if (Date.now() - lastActive > SESSION_DURATION_MS) return 'logged-out'
    return 'authenticated'
  })

  const [sessionExpiresAt, setSessionExpiresAt] = useState<number | null>(() => {
    const lastActive = Number(localStorage.getItem(SESSION_LS_KEY) || '0')
    if (!lastActive) return null
    const expiresAt = lastActive + SESSION_DURATION_MS
    if (expiresAt <= Date.now()) return null
    return expiresAt
  })

  // Prevent React double-render from clobbering state
  const statusRef = useRef(authStatus)

  const setAuthExpired = useCallback(() => {
    if (statusRef.current === 'logged-out') return // don't go backwards
    statusRef.current = 'expired'
    setAuthStatus('expired')
  }, [])

  const setLoggedOut = useCallback(() => {
    performLogout()
    statusRef.current = 'logged-out'
    setAuthStatus('logged-out')
    setSessionExpiresAt(null)
  }, [])

  const resetAuth = useCallback(() => {
    statusRef.current = 'authenticated'
    setAuthStatus('authenticated')
    // Refresh the timestamp when re-authenticated
    const now = Date.now()
    localStorage.setItem(SESSION_LS_KEY, String(now))
    setSessionExpiresAt(now + SESSION_DURATION_MS)
  }, [])

  const refreshSessionTimestamp = useCallback(() => {
    if (statusRef.current !== 'authenticated') return
    const now = Date.now()
    localStorage.setItem(SESSION_LS_KEY, String(now))
    setSessionExpiresAt(now + SESSION_DURATION_MS)
  }, [])

  return (
    <AuthStateContext.Provider
      value={{
        authStatus,
        sessionExpiresAt,
        setAuthExpired,
        setLoggedOut,
        resetAuth,
        refreshSessionTimestamp,
      }}
    >
      {children}
    </AuthStateContext.Provider>
  )
}

export function useAuthState(): AuthState {
  return useContext(AuthStateContext)
}
