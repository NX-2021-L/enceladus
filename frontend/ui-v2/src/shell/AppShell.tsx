import type { ReactNode } from 'react'
import { useEffect } from 'react'
import { RefreshCw } from 'lucide-react'
import { useNavigate, useRouterState } from '@tanstack/react-router'
import { AppLayout, Button, SideNavigation, TopNavigation } from '../design-system'
import { performLogout } from '../auth/logout'
import { useUiStore } from '../store/uiStore'
import { refreshApp } from '../offline/swUpdate'
import { CommandPalette } from './CommandPalette'
import { FeedPane } from './FeedPane'
import { ConflictMergeModal, MutationErrorFlashbar, OfflinePendingFlashbar } from '../components/OfflineLayer'
import enceladusMarkUrl from '../../../design-system-2/assets/logos/enceladus-mark.svg'
import './shell.css'

const LOGOUT_HREF = '__logout__'
const REFRESH_APP_HREF = '__refresh_app__'

const SIDEBAR_ITEMS = [
  { type: 'link' as const, text: 'Projects', href: '/projects' },
  { type: 'link' as const, text: 'Feed', href: '/feed' },
  { type: 'link' as const, text: 'Docs', href: '/docs' },
  { type: 'link' as const, text: 'Skill Library', href: '/skills' },
  { type: 'link' as const, text: 'Governance', href: '/governance' },
  { type: 'link' as const, text: 'Changelog', href: '/changelog' },
  { type: 'link' as const, text: 'Coordination', href: '/coordination' },
  { type: 'link' as const, text: 'Component registry', href: '/component-registry' },
  { type: 'link' as const, text: 'Deployment manager', href: '/deployments' },
  { type: 'link' as const, text: 'Access tokens', href: '/access-tokens' },
  { type: 'link' as const, text: 'Terminal sessions', href: '/terminal-sessions' },
  { type: 'divider' as const },
  {
    type: 'link' as const,
    text: 'App refresh',
    href: REFRESH_APP_HREF,
    icon: <RefreshCw size={16} strokeWidth={1.7} />,
    spin: true,
  },
  { type: 'link' as const, text: 'Log out', href: LOGOUT_HREF },
]

const MOBILE_NAV = [
  { href: '/', label: 'Home' },
  { href: '/projects', label: 'Projects' },
  { href: '/feed', label: 'Feed' },
  { href: '/docs', label: 'Docs' },
]

function resolveActiveHref(pathname: string): string {
  if (pathname === '/') return '/'
  const match = SIDEBAR_ITEMS.find(
    (item) =>
      item.type === 'link' &&
      item.href !== LOGOUT_HREF &&
      item.href !== REFRESH_APP_HREF &&
      pathname.startsWith(item.href ?? ''),
  )
  return match?.href ?? pathname
}

function MobileBottomNav({
  activeHref,
  onNavigate,
}: {
  activeHref: string
  onNavigate: (href: string) => void
}) {
  return (
    <nav className="ev2-shell__bottom-nav" aria-label="Primary">
      {MOBILE_NAV.map(({ href, label }) => {
        const active = href === '/' ? activeHref === '/' : activeHref.startsWith(href)
        return (
          <div
            key={href}
            className={`ev2-shell__bottom-link${active ? ' ev2-shell__bottom-link--active' : ''}`}
          >
            <Button
              variant={active ? 'primary' : 'normal'}
              ariaLabel={label}
              onClick={() => onNavigate(href)}
            >
              {label}
            </Button>
          </div>
        )
      })}
    </nav>
  )
}

/**
 * Cockpit shell on design-system-2 AppLayout: TopNavigation + SideNavigation tray +
 * Feed tools rail + mobile Button bottom bar.
 */
export function AppShell({ children }: { children: ReactNode }) {
  const navigate = useNavigate()
  const pathname = useRouterState({ select: (s) => s.location.pathname })
  const activeHref = resolveActiveHref(pathname)

  const navigationOpen = useUiStore((s) => s.sidebarOpen)
  const setSidebarOpen = useUiStore((s) => s.setSidebarOpen)
  const toggleSidebar = useUiStore((s) => s.toggleSidebar)
  const openCommandPalette = useUiStore((s) => s.openCommandPalette)
  const toolsOpen = useUiStore((s) => s.feedRailOpen)
  const toggleFeedRail = useUiStore((s) => s.toggleFeedRail)
  const setFeedRailOpen = useUiStore((s) => s.setFeedRailOpen)

  useEffect(() => {
    const desktop = window.matchMedia('(min-width: 48.0625rem)')
    const syncSidebar = () => setSidebarOpen(desktop.matches)
    syncSidebar()
    desktop.addEventListener('change', syncSidebar)
    return () => desktop.removeEventListener('change', syncSidebar)
  }, [setSidebarOpen])

  // Band-B polish (ENC-ISS-51x): Escape must dismiss the mobile nav drawer,
  // matching the scrim tap-to-close affordance. Only listens while the
  // drawer is open so it never intercepts Escape elsewhere in the app.
  useEffect(() => {
    if (!navigationOpen) return
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setSidebarOpen(false)
      }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [navigationOpen, setSidebarOpen])

  const followNav = (event: { detail: { href?: string; text?: React.ReactNode } }) => {
    const href = event.detail.href
    if (href === LOGOUT_HREF) {
      performLogout()
      return
    }
    if (href === REFRESH_APP_HREF) {
      // ENC-TSK-M37 -- force-activates the waiting service worker
      // (skipWaiting) and reloads, replacing the old dismiss-only "App
      // update available" banner that never actually called skipWaiting
      // and left probes running against a stale precached shell.
      void refreshApp()
      return
    }
    if (href) {
      navigate({ to: href })
      if (!window.matchMedia('(min-width: 48.0625rem)').matches) {
        setSidebarOpen(false)
      }
    }
  }

  const shellClass = navigationOpen ? 'ev2-shell ev2-shell--nav-open' : 'ev2-shell'

  return (
    <div className={shellClass}>
      {navigationOpen ? (
        <button
          type="button"
          className="ev2-shell__nav-scrim"
          aria-label="Close menu"
          onClick={() => setSidebarOpen(false)}
        />
      ) : null}
      <AppLayout
        topNavigation={
          <TopNavigation
            identity={{ title: 'ENCELADUS', href: '/', iconSrc: enceladusMarkUrl, version: __APP_VERSION__ }}
            utilities={[
              { text: 'Menu', onClick: toggleSidebar },
              { text: 'Search', onClick: openCommandPalette },
              { text: toolsOpen ? 'Hide feed' : 'Feed', onClick: toggleFeedRail },
            ]}
          />
        }
        navigation={
          // No `header` here (ENC-ISS-513 / FND-01): the wordmark already
          // lives once, in TopNavigation. A second "ENCELADUS" brand mark on
          // the drawer was pure duplication.
          <SideNavigation
            items={SIDEBAR_ITEMS}
            activeHref={activeHref}
            onFollow={followNav}
          />
        }
        navigationOpen={navigationOpen}
        content={
          <div className="ev2-shell__content-wrap">
            <div className="ev2-shell__main">{children}</div>
            <MobileBottomNav
              activeHref={activeHref}
              onNavigate={(href) => {
                navigate({ to: href })
              }}
            />
          </div>
        }
        tools={<FeedPane onClose={() => setFeedRailOpen(false)} />}
        toolsOpen={toolsOpen}
      />
      <CommandPalette />
      <OfflinePendingFlashbar />
      <MutationErrorFlashbar />
      <ConflictMergeModal />
    </div>
  )
}
