import { useNavigate } from '@tanstack/react-router'
import { useQuery } from '@tanstack/react-query'
import { Search } from 'lucide-react'
import { projectRegistryQueryOptions, inferRecordNavigation } from '../api/projectRegistry'
import { useUiStore } from '../store/uiStore'
import { DOCUMENT_ROUTE_PATH, trackerRoutePath } from '../routes/recordLink'

/**
 * Command palette. Open-state and query string live in the Zustand UI store
 * (AC-13). Given a `TYPE-...` record id it routes to that record's detail page
 * using the project registry (ENC-TSK-L17 / ENC-ISS-487).
 */
export function CommandPalette() {
  const open = useUiStore((s) => s.commandPaletteOpen)
  const query = useUiStore((s) => s.commandQuery)
  const setCommandQuery = useUiStore((s) => s.setCommandQuery)
  const closeCommandPalette = useUiStore((s) => s.closeCommandPalette)
  const selectRecord = useUiStore((s) => s.selectRecord)
  const navigate = useNavigate()

  const { data: projects = [] } = useQuery(projectRegistryQueryOptions)

  if (!open) return null

  const nav = inferRecordNavigation(query, projects)
  const canGo = nav !== null && (nav.type === 'document' || nav.projectId !== null)

  function submit() {
    if (!nav || !canGo) return
    selectRecord(nav.id)
    closeCommandPalette()
    if (nav.type === 'document') {
      navigate({ to: DOCUMENT_ROUTE_PATH, params: { id: nav.id } })
      return
    }
    navigate({
      to: trackerRoutePath(nav.type),
      params: { project: nav.projectId as string, id: nav.id },
    })
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
          {canGo && nav ? (
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
          )}
        </div>
      </div>
    </div>
  )
}
