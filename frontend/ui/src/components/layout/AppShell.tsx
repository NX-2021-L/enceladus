import { useEffect } from 'react'
import { Outlet } from 'react-router-dom'
import { Header } from './Header'
import { BottomNav } from './BottomNav'
import { LiveFeedProvider } from '../../contexts/LiveFeedContext'
import { useSessionLifecycle } from '../../hooks/useSessionLifecycle'
import { useSessionTimer } from '../../hooks/useSessionTimer'
import { useAuthState } from '../../lib/authState'
import {
  registerSessionExpiredHandler,
  registerLoggedOutHandler,
} from '../../lib/queryClient'
import { SessionExpiredOverlay } from '../shared/SessionExpiredOverlay'
import { LoggedOutScreen } from '../shared/LoggedOutScreen'

export function AppShell() {
  useSessionLifecycle()
  useSessionTimer()

  const { authStatus, setAuthExpired, setLoggedOut } = useAuthState()

  // Register callbacks with the query client.
  // QueryCache.onError → setAuthExpired (triggers refresh overlay)
  // MutationCache.onError → setLoggedOut (after 3 retry cycles exhausted)
  useEffect(() => {
    registerSessionExpiredHandler(setAuthExpired)
    registerLoggedOutHandler(setLoggedOut)
  }, [setAuthExpired, setLoggedOut])

  // 3-state rendering:
  if (authStatus === 'logged-out') return <LoggedOutScreen />
  if (authStatus === 'expired') return <SessionExpiredOverlay />

  // 'authenticated' → normal app
  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 flex flex-col">
      <Header />
      <LiveFeedProvider>
        <main className="flex-1 pb-16 overflow-y-auto">
          <Outlet />
        </main>
      </LiveFeedProvider>
      <BottomNav />
    </div>
  )
}
