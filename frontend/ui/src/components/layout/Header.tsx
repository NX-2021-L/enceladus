import { useState, useRef, useCallback, useEffect } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { ENABLE_REFRESH_LINK } from '../../lib/constants'
import { APP_VERSION } from '../../lib/version'
import { useClickOutside } from '../../hooks/useClickOutside'
import { useAuthState } from '../../lib/authState'

const TITLES: Record<string, string> = {
  '/': 'Dashboard',
  '/projects': 'Projects',
  '/projects/create': 'Create Project',
  '/feed': 'Feed',
  '/documents': 'Documents',
  '/coordination': 'Coordination',
  '/coordination/auth': 'Access Tokens',
}

function resolveTitle(pathname: string): string {
  if (TITLES[pathname]) return TITLES[pathname]
  if (pathname.startsWith('/documents/')) return 'Documents'
  if (pathname.startsWith('/tasks/')) return 'Task Detail'
  if (pathname.startsWith('/issues/')) return 'Issue Detail'
  if (pathname.startsWith('/features/')) return 'Feature Detail'
  if (pathname.startsWith('/projects/')) {
    return pathname === '/projects/create' ? 'Create Project' : 'Project Detail'
  }
  if (pathname.startsWith('/coordination/')) return 'Request Detail'
  if (pathname === '/coordination/auth') return 'Access Tokens'
  return 'Project Status'
}

async function hardRefresh() {
  // 1. Unregister all service workers scoped to this app
  if ('serviceWorker' in navigator) {
    const registrations = await navigator.serviceWorker.getRegistrations()
    await Promise.all(registrations.map((r) => r.unregister()))
  }

  // 2. Clear all Cache Storage entries (workbox precache, etc.)
  if ('caches' in window) {
    const keys = await caches.keys()
    await Promise.all(keys.map((k) => caches.delete(k)))
  }

  // 3. Force a full reload — use a cache-busting query param instead of
  //    reload() because Safari may serve index.html from disk cache even
  //    after SW unregistration + Cache Storage clear.
  const url = new URL(window.location.href)
  url.searchParams.set('_cb', String(Date.now()))
  window.location.href = url.toString()
}

export function Header() {
  const { pathname } = useLocation()
  const title = resolveTitle(pathname)
  const [refreshing, setRefreshing] = useState(false)
  const [menuOpen, setMenuOpen] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)
  const navigate = useNavigate()
  const { setLoggedOut } = useAuthState()

  const closeMenu = useCallback(() => setMenuOpen(false), [])
  useClickOutside(menuRef, closeMenu)

  // Close menu on Escape key
  useEffect(() => {
    if (!menuOpen) return
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') setMenuOpen(false)
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [menuOpen])

  // Close menu on route change
  useEffect(() => {
    setMenuOpen(false)
  }, [pathname])

  const handleRefresh = async () => {
    setMenuOpen(false)
    setRefreshing(true)
    await hardRefresh()
  }

  const handleLogout = () => {
    setMenuOpen(false)
    setLoggedOut()
  }

  return (
    <header className="sticky top-0 z-10 bg-slate-900/95 backdrop-blur border-b border-slate-700/50 px-4 py-3 flex items-center justify-between">
      <h1 className="text-lg font-semibold text-slate-100">{title}</h1>
      <div className="flex items-center gap-3">
        <span className="text-xs text-slate-500 font-mono">v{APP_VERSION}</span>

        <div className="relative" ref={menuRef}>
          <button
            onClick={() => setMenuOpen((prev) => !prev)}
            aria-label="Menu"
            aria-expanded={menuOpen}
            className="text-slate-400 hover:text-slate-200 active:text-slate-100 transition-colors p-1 -mr-1"
          >
            <svg
              className="w-6 h-6"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>

          {menuOpen && (
            <div className="absolute right-0 top-full mt-2 w-44 bg-slate-800 border border-slate-700 rounded-lg shadow-xl py-1 z-20">
              <button
                onClick={() => {
                  setMenuOpen(false)
                  navigate('/coordination')
                }}
                className="w-full text-left px-4 py-3 text-sm text-slate-200 hover:bg-slate-700 active:bg-slate-600 transition-colors"
              >
                Coordination Monitor
              </button>
              <button
                onClick={() => {
                  setMenuOpen(false)
                  navigate('/coordination/auth')
                }}
                className="w-full text-left px-4 py-3 text-sm text-slate-200 hover:bg-slate-700 active:bg-slate-600 transition-colors"
              >
                Access Tokens
              </button>
              {ENABLE_REFRESH_LINK && (
                <button
                  onClick={handleRefresh}
                  disabled={refreshing}
                  className="w-full text-left px-4 py-3 text-sm text-slate-200 hover:bg-slate-700 active:bg-slate-600 disabled:text-slate-500 transition-colors"
                >
                  {refreshing ? 'Refreshing…' : 'Refresh App'}
                </button>
              )}
              <button
                onClick={handleLogout}
                className="w-full text-left px-4 py-3 text-sm text-slate-200 hover:bg-slate-700 active:bg-slate-600 transition-colors"
              >
                Log Out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  )
}
