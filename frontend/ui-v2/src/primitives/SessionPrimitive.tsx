import type { CSSProperties } from 'react'
import { Bot } from 'lucide-react'
import type { Session, SessionWorklogEntry } from '../types/session'
import { PrimitiveCard } from '../components/PrimitiveCard'
import { KeyValuePairs } from '../design-system'

/**
 * SessionPrimitive — ENC-TSK-L35 (B67 PWA2.0 session detail + worklog
 * mirroring). Renders session fields via design-system KeyValuePairs and the
 * mirrored worklog via a lightweight table.
 *
 * Design-system note: the design-system-2 `Table` component
 * (frontend/design-system-2/v2/components/Table/) is NOT re-exported from
 * the ui-v2 design-system barrel (src/design-system/index.{js,d.ts}) today —
 * only KeyValuePairs is. Per the AC-13/AC-14 barrel-only import convention
 * this primitive does not reach around the barrel to import Table directly;
 * it renders the worklog as a semantic HTML <table> styled with the same
 * design tokens PrimitiveCard/MetaRow use elsewhere, matching the visual
 * language without an unauthorized import. See the coordinator report for
 * Table's prop API summary (columnDefinitions/items/header/footer/
 * selectionType/trackBy/sortingColumn/sortingDescending/empty) if the barrel
 * gains a Table export later.
 */
export function SessionPrimitive({ record }: { record: Session }) {
  const history: SessionWorklogEntry[] = record.history ?? []

  return (
    <PrimitiveCard
      recordId={record.session_id}
      kindLabel="Session"
      title={record.agent_type_id || record.session_id}
      status={record.status}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 'var(--space-2)',
          marginBottom: 'var(--space-4)',
          color: 'var(--accent)',
        }}
      >
        <Bot size={16} strokeWidth={1.5} />
        <span
          style={{
            fontFamily: 'var(--font-heading)',
            fontSize: 'var(--text-xs)',
            textTransform: 'uppercase',
            letterSpacing: 'var(--tracking-label)',
          }}
        >
          {record.runtime}
        </span>
      </div>

      <div style={{ marginBottom: 'var(--space-6)' }}>
        <KeyValuePairs
          columns={2}
          items={[
            { label: 'Session ID', value: record.session_id, mono: true },
            { label: 'Agent Type', value: record.agent_type_id, mono: true },
            { label: 'Parent Session', value: record.parent_session_id || 'root', mono: true },
            { label: 'Runtime', value: record.runtime },
            { label: 'Status', value: record.status },
            { label: 'Created At', value: record.created_at || '—', mono: true },
            { label: 'Claimed At', value: record.claimed_at || '—', mono: true },
            { label: 'Updated At', value: record.updated_at || '—', mono: true },
            { label: 'Last Activity At', value: record.last_activity_at || '—', mono: true },
            { label: 'SCI Token', value: record.sci_token_id || '—', mono: true },
          ]}
        />
      </div>

      <h4
        style={{
          fontFamily: 'var(--font-heading)',
          fontSize: 'var(--text-sm)',
          fontWeight: 'var(--fw-medium)',
          textTransform: 'uppercase',
          letterSpacing: 'var(--tracking-label)',
          color: 'var(--fg-muted)',
          margin: '0 0 var(--space-3)',
        }}
      >
        Mirrored Worklog
      </h4>

      {history.length === 0 ? (
        <p
          style={{
            fontFamily: 'var(--font-body)',
            fontSize: 'var(--text-sm)',
            color: 'var(--fg-muted)',
          }}
        >
          No worklog entries have been mirrored onto this session yet.
        </p>
      ) : (
        <table
          style={{
            width: '100%',
            borderCollapse: 'collapse',
            fontFamily: 'var(--font-body)',
            fontSize: 'var(--text-sm)',
          }}
        >
          <thead>
            <tr style={{ background: 'var(--bg-surface-alt)' }}>
              <th style={worklogHeaderCellStyle}>Timestamp</th>
              <th style={worklogHeaderCellStyle}>Source Record</th>
              <th style={worklogHeaderCellStyle}>Description</th>
            </tr>
          </thead>
          <tbody>
            {history.map((entry, index) => (
              <tr key={`${entry.timestamp}-${index}`} style={{ borderTop: 'var(--border-divider)' }}>
                <td style={{ ...worklogCellStyle, fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>
                  {entry.timestamp}
                </td>
                <td style={worklogCellStyle}>
                  {entry.source_record_type && entry.source_record_id
                    ? `${entry.source_record_type}:${entry.source_record_id}`
                    : '—'}
                </td>
                <td style={worklogCellStyle}>{entry.description}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </PrimitiveCard>
  )
}

const worklogHeaderCellStyle: CSSProperties = {
  textAlign: 'left',
  padding: 'var(--space-2) var(--space-3)',
  fontFamily: 'var(--font-heading)',
  fontSize: 'var(--text-xs)',
  fontWeight: 'var(--fw-medium)',
  textTransform: 'uppercase',
  letterSpacing: 'var(--tracking-label)',
  color: 'var(--fg-muted)',
}

const worklogCellStyle: CSSProperties = {
  padding: 'var(--space-2) var(--space-3)',
  color: 'var(--fg)',
  verticalAlign: 'top',
}
