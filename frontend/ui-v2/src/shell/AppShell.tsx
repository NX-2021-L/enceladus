import type { ReactNode } from 'react'
import { useEffect } from 'react'
import { RefreshCw } from 'lucide-react'
import { useNavigate, useRouterState } from '@tanstack/react-router'
import { AppLayout, SideNavigation, TopNavigation } from '../design-system'
import { performLogout } from '../auth/logout'
import { useUiStore } from '../store/uiStore'
import { refreshApp } from '../offline/swUpdate'
import { CommandPalette } from './CommandPalette'
import { useCommandNavigation } from './useCommandNavigation'
import { ConflictMergeModal, MutationErrorFlashbar, OfflinePendingFlashbar } from '../components/OfflineLayer'
import enceladusMarkUrl from '../../../design-system-2/assets/logos/enceladus-mark.svg'
import './shell.css'

const LOGOUT_HREF = '__logout__'
const REFRESH_APP_HREF = '__refresh_app__'
const DESKTOP_QUERY = '(min-width: 48.0625rem)'

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

/**
 * Cockpit shell on design-system-2 AppLayout: TopNavigation + SideNavigation
 * tray.
 *
 * ENC-TSK-M75 (io UAT 2026-07-12): the mobile bottom nav bar
 * (Home/Projects/Feed/Docs) was removed. Per io decision the TopNavigation
 * "Menu" button + SideNavigation drawer is now the single primary navigation
 * on ALL viewports, so the redundant bottom bar (which rendered inside the
 * scroll flow on record detail pages) no longer exists.
 *
 * ENC-TSK-N46 (ENC-ISS-552): the top-nav "Feed" toggle + its FeedPane tools
 * rail were removed as a stale duplicate of the dedicated /feed page (still
 * reachable via the drawer link above, untouched). The nav's utilities row
 * is now just Menu, rightmost; a thin search box sits before it and opens
 * CommandPalette -- full-screen on mobile (tap-to-expand), anchored under
 * the box on desktop (widen-in-place), per viewport at focus time.
 */
export function AppShell({ children }: { children: ReactNode }) {
  const navigate = useNavigate()
  const pathname = useRouterState({ select: (s) => s.location.pathname })
  const activeHref = resolveActiveHref(pathname)

  const navigationOpen = useUiStore((s) => s.sidebarOpen)
  const setSidebarOpen = useUiStore((s) => s.setSidebarOpen)
  const toggleSidebar = useUiStore((s) => s.toggleSidebar)
  const commandPaletteOpen = useUiStore((s) => s.commandPaletteOpen)
  const commandQuery = useUiStore((s) => s.commandQuery)
  const setCommandQuery = useUiStore((s) => s.setCommandQuery)
  const openCommandPalette = useUiStore((s) => s.openCommandPalette)
  const closeCommandPalette = useUiStore((s) => s.closeCommandPalette)
  // Only used for the desktop anchored search box's own Enter handling --
  // the mobile full-screen overlay has its own input + submit binding
  // inside CommandPalette, untouched here.
  const { submit: submitCommand } = useCommandNavigation(commandQuery)

  useEffect(() => {
    const desktop = window.matchMedia(DESKTOP_QUERY)
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
      if (!window.matchMedia(DESKTOP_QUERY).matches) {
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
            search={{
              value: commandQuery,
              onChange: setCommandQuery,
              placeholder: 'Search…',
              // Mobile taps expand to the existing full-screen overlay;
              // desktop focus widens the box in place and opens the
              // anchored dropdown instead (ENC-TSK-N46).
              onFocus: () => openCommandPalette(window.matchMedia(DESKTOP_QUERY).matches),
              onBlur: () => {
                // Only the anchored (desktop) mode should close on blur --
                // on mobile, focus moving into CommandPalette's own
                // full-screen input fires this same blur and would
                // otherwise close the overlay the instant it opens.
                if (commandPaletteOpen && window.matchMedia(DESKTOP_QUERY).matches) {
                  closeCommandPalette()
                }
              },
              onKeyDown: (event) => {
                if (event.key === 'Enter') submitCommand()
                if (event.key === 'Escape') {
                  closeCommandPalette()
                  event.currentTarget.blur()
                }
              },
            }}
            utilities={[{ text: 'Menu', onClick: toggleSidebar }]}
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
          </div>
        }
      />
      <CommandPalette />
      <OfflinePendingFlashbar />
      <MutationErrorFlashbar />
      <ConflictMergeModal />
    </div>
  )
}
