import { Search } from 'lucide-react'
import { useUiStore } from '../store/uiStore'
import { useCommandNavigation } from './useCommandNavigation'

/**
 * Command palette. Open-state, anchor mode, and query string live in the
 * Zustand UI store (AC-13). Given a `TYPE-...` record id it routes to that
 * record's detail page using the project registry (ENC-TSK-L17 / ENC-ISS-487).
 *
 * Two render modes, both driven by `commandPaletteAnchored` (ENC-TSK-N46):
 *  - false (mobile tap target): full-screen centered modal with its own
 *    input, unchanged from the original design.
 *  - true (desktop widen-in-place): a small dropdown anchored under the
 *    top-nav search box. Typing happens in that nav input (AppShell owns
 *    it, sharing `commandQuery`/`setCommandQuery`), so this mode renders
 *    only the results/hint row, not a second input.
 */
export function CommandPalette() {
  const open = useUiStore((s) => s.commandPaletteOpen)
  const anchored = useUiStore((s) => s.commandPaletteAnchored)
  const query = useUiStore((s) => s.commandQuery)
  const setCommandQuery = useUiStore((s) => s.setCommandQuery)
  const closeCommandPalette = useUiStore((s) => s.closeCommandPalette)
  const { nav, canGo, submit } = useCommandNavigation(query)

  if (!open) return null

  const hint = canGo && nav ? (
    <span>
      Enter to open{' '}
      <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>
        {nav.id}
      </span>{' '}
      as {nav.type}
      {nav.projectId ? (
        <>
          {' '}
          in{' '}
          <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>
            {nav.projectId}
          </span>
        </>
      ) : null}
    </span>
  ) : nav && nav.type !== 'document' && !nav.projectId ? (
    <span>Unknown project prefix — check GET /api/v1/projects registry</span>
  ) : (
    <span>Type a record id (TSK / ISS / FTR / PLN / LSN / DOC)</span>
  )

  if (anchored) {
    return (
      <div
        role="listbox"
        aria-label="Search results"
        style={{
          position: 'fixed',
          top: '60px',
          right: '20px',
          width: 'min(360px, calc(100vw - 40px))',
          background: 'var(--bg-surface)',
          border: 'var(--border-hover)',
          borderRadius: 'var(--radius-lg)',
          boxShadow: 'var(--shadow-lg), var(--glow-teal)',
          padding: 'var(--space-3) var(--space-4)',
          fontSize: 'var(--text-xs)',
          color: 'var(--fg-muted)',
          fontFamily: 'var(--font-body)',
          zIndex: 50,
        }}
      >
        {hint}
      </div>
    )
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Command palette"
      onClick={closeCommandPalette}
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(10,10,15,0.72)',
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'center',
        paddingTop: '14vh',
        zIndex: 50,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 'min(560px, 92vw)',
          background: 'var(--bg-surface)',
          border: 'var(--border-hover)',
          borderRadius: 'var(--radius-xl)',
          boxShadow: 'var(--shadow-lg), var(--glow-teal)',
          overflow: 'hidden',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', padding: 'var(--space-4) var(--space-5)' }}>
          <Search size={18} strokeWidth={1.5} color="var(--accent)" />
          <input
            autoFocus
            value={query}
            onChange={(e) => setCommandQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') submit()
              if (e.key === 'Escape') closeCommandPalette()
            }}
            placeholder="Jump to record — e.g. ENC-TSK-K21"
            style={{
              flex: 1,
              background: 'transparent',
              border: 'none',
              outline: 'none',
              color: 'var(--fg)',
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-base)',
            }}
          />
        </div>
        <div
          style={{
            borderTop: 'var(--border-divider)',
            padding: 'var(--space-3) var(--space-5)',
            fontSize: 'var(--text-xs)',
            color: 'var(--fg-muted)',
            fontFamily: 'var(--font-body)',
          }}
        >
          {hint}
        </div>
      </div>
    </div>
  )
}
