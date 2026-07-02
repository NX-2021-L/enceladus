import { Link } from '@tanstack/react-router'
import { ArrowUpRight } from 'lucide-react'
import { RECORD_ROUTE_PATH } from './recordLink'
import { RecordId } from '../components/RecordId'
import type { RecordType } from '../types/records'

// ENC-TSK-K70: sample IDs point at records verified PRESENT in the GAMMA
// tables (devops-project-tracker-gamma / documents-gamma) — the prior IDs
// existed only in prod, so every card 404ed against the gamma shadow data
// (io gamma-native data decision, ENC-PLN-066). Re-verify against the gamma
// list API before changing.
const ENTRY: Array<{ type: RecordType; label: string; sampleId: string }> = [
  { type: 'task', label: 'Task', sampleId: 'ENC-TSK-H68' },
  { type: 'issue', label: 'Issue', sampleId: 'ENC-ISS-058' },
  { type: 'feature', label: 'Feature', sampleId: 'ENC-FTR-096' },
  { type: 'plan', label: 'Plan', sampleId: 'ENC-PLN-051' },
  { type: 'lesson', label: 'Lesson', sampleId: 'ENC-LSN-057' },
  { type: 'document', label: 'Document', sampleId: 'DOC-12A69AF1D3BE' },
]

export function HomeRoute() {
  return (
    <div style={{ maxWidth: '72ch' }}>
      <p
        style={{
          fontFamily: 'var(--font-body)',
          fontSize: 'var(--text-xs)',
          textTransform: 'uppercase',
          letterSpacing: 'var(--tracking-label)',
          color: 'var(--fg-muted)',
          margin: '0 0 var(--space-2)',
        }}
      >
        PWA 2.0 · Governance Cockpit
      </p>
      <h1
        style={{
          fontFamily: 'var(--font-heading)',
          fontWeight: 'var(--fw-bold)',
          fontSize: 'var(--text-4xl)',
          lineHeight: 'var(--lh-tight)',
          letterSpacing: 'var(--tracking-tight)',
          color: 'var(--fg-display)',
          margin: '0 0 var(--space-4)',
        }}
      >
        Six primitives, one canvas.
      </h1>
      <p style={{ color: 'var(--fg)', fontSize: 'var(--text-lg)', lineHeight: 'var(--lh-relaxed)' }}>
        Every record type resolves through a typed query-options factory and a
        route-level Suspense boundary. Open one:
      </p>

      <ul
        style={{
          listStyle: 'none',
          padding: 0,
          margin: 'var(--space-6) 0 0',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
          gap: 'var(--space-3)',
        }}
      >
        {ENTRY.map(({ type, label, sampleId }) => (
          <li key={type}>
            <Link
              to={RECORD_ROUTE_PATH[type]}
              params={{ id: sampleId }}
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 'var(--space-2)',
                padding: 'var(--space-4)',
                background: 'var(--bg-surface)',
                border: 'var(--border-subtle)',
                borderRadius: 'var(--radius-lg)',
                textDecoration: 'none',
              }}
            >
              <span
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  fontFamily: 'var(--font-heading)',
                  fontSize: 'var(--text-sm)',
                  fontWeight: 'var(--fw-medium)',
                  color: 'var(--fg-display)',
                }}
              >
                {label}
                <ArrowUpRight size={15} strokeWidth={1.5} color="var(--accent)" />
              </span>
              <RecordId id={sampleId} />
            </Link>
          </li>
        ))}
      </ul>
    </div>
  )
}
