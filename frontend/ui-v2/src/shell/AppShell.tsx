import type { ReactNode } from 'react'
import { Header } from './Header'
import { Sidebar } from './Sidebar'
import { FeedPane } from './FeedPane'
import { CommandPalette } from './CommandPalette'

/**
 * App shell: header on top, then a row of [sidebar | feed pane | routed content].
 * The routed <Outlet /> content is passed as `children` from the root route.
 */
export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: '100vh' }}>
      <Header />
      <div style={{ display: 'flex', flex: 1, minHeight: 0 }}>
        <Sidebar />
        <FeedPane />
        <main
          style={{
            flex: 1,
            minWidth: 0,
            overflowY: 'auto',
            padding: 'var(--space-8)',
            background: 'var(--bg)',
          }}
        >
          {children}
        </main>
      </div>
      <CommandPalette />
    </div>
  )
}
