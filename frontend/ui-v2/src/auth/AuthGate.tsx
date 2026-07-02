import type { ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { probeSession } from '../api/client'
import { LoggedOutScreen } from './LoggedOutScreen'

/**
 * ENC-TSK-K98 — hard auth gate.
 *
 * Wraps the ENTIRE app (mounted above the realtime feed provider and the
 * router in main.tsx) so an unauthenticated visitor sees ONLY the sign-in
 * screen — no shell, no feed pane, no snapshot fetch, nothing. On load we probe
 * an authenticated endpoint once:
 *   - pending  -> a minimal branded splash (the probe is a single fast request)
 *   - error    -> LoggedOutScreen (401/SessionExpiredError — or any failure to
 *                 confirm a live session; we fail closed)
 *   - success  -> render the app
 *
 * This is the proactive counterpart to the router's defaultErrorComponent
 * (ENC-TSK-K95): that catches a 401 thrown mid-navigation; this stops the app
 * from mounting at all until a session is confirmed.
 */
export function AuthGate({ children }: { children: ReactNode }) {
  const { status } = useQuery({
    queryKey: ['auth', 'session'],
    queryFn: async ({ signal }) => {
      await probeSession({ signal })
      return true
    },
    retry: false,
    staleTime: 5 * 60_000,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  })

  if (status === 'success') return <>{children}</>
  if (status === 'error') return <LoggedOutScreen />
  return <AuthSplash />
}

/** Minimal pre-auth splash — design tokens only, no shell, no data. */
function AuthSplash() {
  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'var(--enc-void)',
      }}
    >
      <p
        style={{
          fontFamily: 'var(--font-body)',
          fontSize: 'var(--text-xs)',
          textTransform: 'uppercase',
          letterSpacing: 'var(--tracking-label)',
          color: 'var(--fg-muted)',
          margin: 0,
        }}
      >
        Enceladus · Governance Cockpit
      </p>
    </div>
  )
}
