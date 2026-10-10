import type { ReactNode } from 'react'
import { RefreshCw } from 'lucide-react'
import { useNavigate, useRouterState } from '@tanstack/react-router'
import { KitShell } from '@io-kit/shell/react'
import type { RouterAdapter } from '@io-kit/shell/react'
import { performLogout } from '../auth/logout'
import { useAuthSession } from '../auth/useCan'
import { useUiStore } from '../store/uiStore'
import { refreshApp } from '../offline/swUpdate'
import { CommandPalette } from './CommandPalette'
import { useCommandNavigation } from './useCommandNavigation'
import { NAV_REGISTRY } from './navRegistry'
import { ConflictMergeModal, MutationErrorFlashbar, OfflinePendingFlashbar } from '../components/OfflineLayer'
import './shell.css'

const DESKTOP_QUERY = '(min-width: 48.0625rem)'

/**
 * DVP-TSK-860: cockpit frame on @io-kit/shell KitShell (48rem breakpoint,
 * bottom bar / rail / sidebar from one registry, safe-area insets, update
 * toast). Navigation derives from the caps snapshot + PermissionManifest in
 * navRegistry.ts. The cockpit's own CommandPalette (route/record search) is
 * kept, so the kit palette is off to avoid a second Ctrl/Cmd+K handler.
 */
export function AppShell({ children }: { children: ReactNode }) {
  const navigate = useNavigate()
  const pathname = useRouterState({ select: (s) => s.location.pathname })

  const commandPaletteOpen = useUiStore((s) => s.commandPaletteOpen)
  const commandQuery = useUiStore((s) => s.commandQuery)
  const setCommandQuery = useUiStore((s) => s.setCommandQuery)
  const openCommandPalette = useUiStore((s) => s.openCommandPalette)
  const closeCommandPalette = useUiStore((s) => s.closeCommandPalette)
  const { submit: submitCommand } = useCommandNavigation(commandQuery)

  const router: RouterAdapter = {
      pathname,
      navigate: (to: string) => void navigate({ to }),
  }

  // Groups come from the @io-kit/auth principal (DVP-TSK-861); display only.
  const session = useAuthSession()
  const user = { sub: session.principal?.sub, groups: session.principal?.groups ?? [] }

  return (
    <>
      <KitShell
        registry={NAV_REGISTRY}
        user={user}
        router={router}
        stack="enceladus"
        title="ENCELADUS"
        palette={false}
        slots={{
          headerEnd: (
            <input
              type="search"
              className="ev2-shell__search"
              aria-label="Search"
              value={commandQuery}
              placeholder="Search…"
              onChange={(e) => setCommandQuery(e.target.value)}
              onFocus={() => openCommandPalette(window.matchMedia(DESKTOP_QUERY).matches)}
              onBlur={() => {
                if (commandPaletteOpen && window.matchMedia(DESKTOP_QUERY).matches) closeCommandPalette()
              }}
              onKeyDown={(event) => {
                if (event.key === 'Enter') submitCommand()
                if (event.key === 'Escape') {
                  closeCommandPalette()
                  event.currentTarget.blur()
                }
              }}
            />
          ),
          drawerFooter: (
            <div className="ev2-shell__drawer-actions">
              <button type="button" onClick={() => void refreshApp()}>
                <RefreshCw size={16} strokeWidth={1.7} /> App refresh
              </button>
              <button type="button" onClick={() => performLogout()}>
                Log out
              </button>
            </div>
          ),
        }}
      >
        <div className="ev2-shell__main">{children}</div>
      </KitShell>
      <CommandPalette />
      <OfflinePendingFlashbar />
      <MutationErrorFlashbar />
      <ConflictMergeModal />
    </>
  )
}
