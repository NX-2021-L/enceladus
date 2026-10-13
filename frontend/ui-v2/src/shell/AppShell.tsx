import type { ReactNode } from 'react'
import { useEffect, useLayoutEffect, useRef } from 'react'
import { RefreshCw } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate, useRouterState } from '@tanstack/react-router'
import { ScrollRegion, ScrollTopZone, useScrollActivity, useScrollToTop, useVisualViewportFrame } from '@io-kit/shell/react'
import { AppLayout, SideNavigation, TopNavigation } from '../design-system'
import { performLogout } from '../auth/logout'
import { redirectToAddPasskey } from '../auth/authConfig'
import { PasskeyResultNotice } from '../auth/PasskeyResultNotice'
import { useUiStore } from '../store/uiStore'
import { refreshApp } from '../offline/swUpdate'
import { projectRegistryQueryOptions } from '../api/projectRegistry'
import { useEnceladusCorpus } from '../search/CorpusProvider'
import { HeaderSearch } from './HeaderSearch'
import { ConflictMergeModal, MutationErrorFlashbar, OfflinePendingFlashbar } from '../components/OfflineLayer'
import enceladusMarkUrl from '../../../design-system-2/assets/logos/enceladus-mark.svg'
import './shell.css'

const LOGOUT_HREF = '__logout__'
const ADD_PASSKEY_HREF = '__add_passkey__'
const REFRESH_APP_HREF = '__refresh_app__'
const DESKTOP_QUERY = '(min-width: 48.0625rem)'
// DVP-TSK-A09 (R16): split routes that fill the height from 960px (the page scroller does not scroll there).
const FILL_ROUTES = ['/feed', '/docs']

const SIDEBAR_ITEMS = [
  { type: 'link' as const, text: 'Projects', href: '/projects' },
  { type: 'link' as const, text: 'Feed', href: '/feed' },
  { type: 'link' as const, text: 'Docs', href: '/docs' },
  { type: 'link' as const, text: 'Skill Library', href: '/skills' },
  { type: 'link' as const, text: 'Governance', href: '/governance' },
  { type: 'link' as const, text: 'Changelog', href: '/changelog' },
  { type: 'link' as const, text: 'Coordination', href: '/coordination' },
  // ENC-TSK-O40: the escalations decision surface. Restored as a first-class
  // nav item — CoordinationRoute's tab is a read-only monitor view and cannot
  // approve or deny, and approve/deny have no MCP path by design, so this is
  // the ONLY way a decision can be made once v4 is the production surface.
  { type: 'link' as const, text: 'Escalations', href: '/escalations' },
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
  // DVP-TSK-B24: Cognito-native passkey enrolment on the managed-login v2 custom domain.
  { type: 'link' as const, text: 'Add a passkey', href: ADD_PASSKEY_HREF },
  { type: 'link' as const, text: 'Log out', href: LOGOUT_HREF },
]

function resolveActiveHref(pathname: string): string {
  if (pathname === '/') return '/'
  const match = SIDEBAR_ITEMS.find(
    (item) =>
      item.type === 'link' &&
      item.href !== LOGOUT_HREF &&
      item.href !== ADD_PASSKEY_HREF &&
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

  // DVP-TSK-956: the ds2 frame scrolls ONE inner element (.ev2-al__content,
  // owned by AppLayout), not the window. Find it once, mark it as the kit's
  // scroller convention, and drive tap-to-top / keyboard reveal from it.
  const frameRef = useRef<HTMLDivElement>(null)
  const scrollerRef = useRef<HTMLElement | null>(null)
  useLayoutEffect(() => {
    const scroller = frameRef.current?.querySelector<HTMLElement>('.ev2-al__content') ?? null
    scrollerRef.current = scroller
    scroller?.setAttribute('data-io-scroller', '')
    // R16: the ONE page scroll owner below 960px, themed and quiet (.io-scroll), the tap-to-top target.
    scroller?.classList.add('io-scroll')
  }, [])
  useScrollActivity(scrollerRef)
  useEffect(() => {
    const fill = FILL_ROUTES.some((p) => pathname === p || pathname.startsWith(`${p}/`))
    scrollerRef.current?.toggleAttribute('data-ev2-fill', fill)
  }, [pathname])
  const scrollToTop = useScrollToTop(scrollerRef)
  // Keyboard: sizes the frame to the visible area (shell.css) and reveals the
  // focused field inside the scroller; the fixed record action bar is hidden
  // while the keyboard is open.
  useVisualViewportFrame({ target: frameRef })

  const navigationOpen = useUiStore((s) => s.sidebarOpen)
  const setSidebarOpen = useUiStore((s) => s.setSidebarOpen)
  const toggleSidebar = useUiStore((s) => s.toggleSidebar)
  const corpus = useEnceladusCorpus()
  const { data: projects = [] } = useQuery(projectRegistryQueryOptions)

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
    if (href === ADD_PASSKEY_HREF) {
      redirectToAddPasskey()
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
      // Re-tapping the active destination scrolls to the top (kit Nav default).
      if (href === activeHref) scrollToTop()
      navigate({ to: href })
      if (!window.matchMedia(DESKTOP_QUERY).matches) {
        setSidebarOpen(false)
      }
    }
  }

  const shellClass = navigationOpen ? 'ev2-shell ev2-shell--nav-open' : 'ev2-shell'

  return (
    <div className={shellClass} ref={frameRef}>
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
          <ScrollTopZone scrollerRef={scrollerRef} className="io-safe-top ev2-shell__bar">
            <TopNavigation
              identity={{ title: 'ENCELADUS', href: '/', iconSrc: enceladusMarkUrl, version: __APP_VERSION__ }}
              utilities={[
                {
                  type: 'node',
                  node: <HeaderSearch rows={corpus.rows} projects={projects} onNavigate={(href) => {
                    // The launcher hands over a URL (/feed?q=...); the router wants path + search object.
                    const url = new URL(href, window.location.origin)
                    void navigate({ to: url.pathname, search: Object.fromEntries(url.searchParams) as never })
                  }} />,
                },
                { text: 'Menu', onClick: toggleSidebar },
              ]}
            />
          </ScrollTopZone>
        }
        navigation={
          // No `header` here (ENC-ISS-513 / FND-01): the wordmark already
          // lives once, in TopNavigation. A second "ENCELADUS" brand mark on
          // the drawer was pure duplication.
          <ScrollRegion className="ev2-shell__nav">
            <SideNavigation
              items={SIDEBAR_ITEMS}
              activeHref={activeHref}
              onFollow={followNav}
            />
          </ScrollRegion>
        }
        navigationOpen={navigationOpen}
        content={
          <div className="ev2-shell__content-wrap">
            <div className="ev2-shell__main">{children}</div>
          </div>
        }
      />
      <PasskeyResultNotice />
      <OfflinePendingFlashbar />
      <MutationErrorFlashbar />
      <ConflictMergeModal />
    </div>
  )
}
