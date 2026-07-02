import { useUiStore } from '../store/uiStore'
import type { RecordType } from '../types/records'

const FILTERABLE: RecordType[] = ['task', 'issue', 'feature', 'plan', 'lesson', 'document']

/**
 * Feed placeholder pane. Live feed data lands in a later task; here it renders
 * the UI-only filter surface driven entirely by the Zustand store (AC-13 — no
 * server state, no useState holding record fields).
 */
export function FeedPane() {
  const filters = useUiStore((s) => s.filters)
  const toggleFilterType = useUiStore((s) => s.toggleFilterType)

  return (
    <aside
      style={{
        width: 260,
        flexShrink: 0,
        borderRight: 'var(--border-subtle)',
        background: 'var(--bg-surface)',
        padding: 'var(--space-5)',
        overflowY: 'auto',
      }}
    >
      <h4
        style={{
          fontFamily: 'var(--font-heading)',
          fontSize: 'var(--text-xs)',
          fontWeight: 'var(--fw-bold)',
          textTransform: 'uppercase',
          letterSpacing: '0.09em',
          color: 'var(--accent)',
          margin: '0 0 var(--space-4)',
        }}
      >
        Feed
      </h4>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)', marginBottom: 'var(--space-5)' }}>
        {FILTERABLE.map((type) => {
          const active = filters.recordTypes.includes(type)
          return (
            <button
              key={type}
              type="button"
              onClick={() => toggleFilterType(type)}
              style={{
                fontFamily: 'var(--font-heading)',
                fontSize: 'var(--text-xs)',
                textTransform: 'uppercase',
                letterSpacing: 'var(--tracking-label)',
                padding: '2px var(--space-2)',
                borderRadius: 'var(--radius-sm)',
                border: `1px solid ${active ? 'var(--accent)' : 'rgba(61,155,168,0.2)'}`,
                background: active ? 'rgba(61,155,168,0.12)' : 'transparent',
                color: active ? 'var(--accent-hover)' : 'var(--fg-muted)',
                cursor: 'pointer',
              }}
            >
              {type}
            </button>
          )
        })}
      </div>

      <p style={{ color: 'var(--fg-muted)', fontSize: 'var(--text-sm)', lineHeight: 'var(--lh-relaxed)' }}>
        Live feed lands in a later task. Filters above are UI-only state held in
        the Zustand store.
      </p>
    </aside>
  )
}
