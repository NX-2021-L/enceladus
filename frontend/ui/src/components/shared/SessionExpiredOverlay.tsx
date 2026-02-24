import { useState, useEffect, useRef } from 'react'
import { refreshCredentials } from '../../api/auth'
import { useAuthState } from '../../lib/authState'

/**
 * Transient overlay displayed when authStatus === 'expired'.
 *
 * 1. Shows spinner + "Refreshing session..."
 * 2. Auto-calls refreshCredentials() (POST /api/v1/auth/refresh)
 * 3. On success: resetAuth() → dismiss overlay → normal app resumes
 * 4. On failure: setLoggedOut() → AppShell renders LoggedOutScreen
 *
 * A fallback "Sign in again" button appears after 5 seconds in case
 * the refresh call hangs or encounters a network issue.
 */
export function SessionExpiredOverlay() {
  const { resetAuth, setLoggedOut, refreshSessionTimestamp } = useAuthState()
  const [showFallback, setShowFallback] = useState(false)
  const attemptedRef = useRef(false)

  useEffect(() => {
    // Prevent React StrictMode double-fire
    if (attemptedRef.current) return
    attemptedRef.current = true

    let cancelled = false

    async function attemptRefresh() {
      try {
        const ok = await refreshCredentials()
        if (cancelled) return
        if (ok) {
          refreshSessionTimestamp()
          resetAuth()
        } else {
          setLoggedOut()
        }
      } catch {
        if (!cancelled) {
          setLoggedOut()
        }
      }
    }

    attemptRefresh()
    return () => { cancelled = true }
  }, [resetAuth, setLoggedOut, refreshSessionTimestamp])

  // Fallback button after 5 seconds
  useEffect(() => {
    const t = setTimeout(() => setShowFallback(true), 5_000)
    return () => clearTimeout(t)
  }, [])

  return (
    <div className="fixed inset-0 z-50 flex flex-col items-center justify-center bg-slate-900 text-center px-4">
      {/* Spinner */}
      <svg
        className="w-10 h-10 text-slate-500 mb-4 animate-spin"
        fill="none"
        viewBox="0 0 24 24"
        aria-hidden="true"
      >
        <circle
          className="opacity-25"
          cx="12"
          cy="12"
          r="10"
          stroke="currentColor"
          strokeWidth="4"
        />
        <path
          className="opacity-75"
          fill="currentColor"
          d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
        />
      </svg>
      <p className="text-slate-300 text-sm font-medium">Refreshing session&hellip;</p>
      <p className="text-slate-500 text-xs mt-1">Please wait</p>

      {/* Fallback: shown after 5 s if refresh hasn't resolved */}
      {showFallback && (
        <button
          type="button"
          onClick={() => setLoggedOut()}
          className="mt-6 text-xs text-sky-400 underline underline-offset-2"
        >
          Sign in again
        </button>
      )}
    </div>
  )
}
