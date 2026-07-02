import { useNavigate } from '@tanstack/react-router'
import { Search } from 'lucide-react'
import { useUiStore } from '../store/uiStore'
import { RECORD_ROUTE_PATH } from '../routes/recordLink'
import type { RecordType } from '../types/records'

/**
 * Command palette. Open-state and query string live in the Zustand UI store
 * (AC-13). Given a `TYPE-...` record id it routes to that record's detail page.
 */
const PREFIX_TO_TYPE: Record<string, RecordType> = {
  TSK: 'task',
  ISS: 'issue',
  FTR: 'feature',
  PLN: 'plan',
  LSN: 'lesson',
  DOC: 'document',
}

function inferType(query: string): RecordType | null {
  const upper = query.toUpperCase()
  if (upper.startsWith('DOC-')) return 'document'
  const mid = upper.split('-')[1]
  return (mid && PREFIX_TO_TYPE[mid]) ?? null
}

export function CommandPalette() {
  const open = useUiStore((s) => s.commandPaletteOpen)
  const query = useUiStore((s) => s.commandQuery)
  const setCommandQuery = useUiStore((s) => s.setCommandQuery)
  const closeCommandPalette = useUiStore((s) => s.closeCommandPalette)
  const selectRecord = useUiStore((s) => s.selectRecord)
  const navigate = useNavigate()

  if (!open) return null

  const type = inferType(query)
  const canGo = type !== null && query.trim().length > 0

  function submit() {
    if (!type || !canGo) return
    const id = query.trim().toUpperCase()
    selectRecord(id)
    closeCommandPalette()
    navigate({ to: RECORD_ROUTE_PATH[type], params: { id } })
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
          {canGo ? (
            <span>
              Enter to open{' '}
              <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>
                {query.trim().toUpperCase()}
              </span>{' '}
              as {type}
            </span>
          ) : (
            <span>Type a record id (TSK / ISS / FTR / PLN / LSN / DOC)</span>
          )}
        </div>
      </div>
    </div>
  )
}
