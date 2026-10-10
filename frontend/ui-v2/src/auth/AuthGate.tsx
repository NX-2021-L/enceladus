import type { ReactNode } from 'react'
import { AuthProvider, useSession } from '@io-kit/auth/react'
import { auth } from './authClient'
import { installReauthFetch } from './reauthFetch'
import { LoggedOutScreen } from './LoggedOutScreen'

// ENC-ISS-546: every same-origin /api/v1 call re-auths on mid-session expiry.
if (typeof window !== 'undefined') window.fetch = installReauthFetch(auth)

/**
 * ENC-TSK-K98 hard auth gate, now on @io-kit/auth (DVP-TSK-861). The kit client
 * boots by refreshing from the HttpOnly cookie:
 *   loading  -> branded splash (no shell, no data)
 *   sign-in  -> LoggedOutScreen (fails closed)
 *   app      -> render the app
 */
export function AuthGate({ children }: { children: ReactNode }) {
  return (
    <AuthProvider client={auth}>
      <Gate>{children}</Gate>
    </AuthProvider>
  )
}

function Gate({ children }: { children: ReactNode }) {
  const s = useSession()
  if (s.surface === 'app') return <>{children}</>
  if (s.surface === 'sign-in') return <LoggedOutScreen />
  return <AuthSplash />
}

/** Minimal pre-auth splash — design tokens only, no shell, no data. */
function AuthSplash() {
  return (
    <div style={{ position: 'fixed', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--enc-void)' }}>
      <p style={{ fontFamily: 'var(--font-body)', fontSize: 'var(--text-xs)', textTransform: 'uppercase', letterSpacing: 'var(--tracking-label)', color: 'var(--fg-muted)', margin: 0 }}>
        Enceladus · Governance Cockpit
      </p>
    </div>
  )
}
