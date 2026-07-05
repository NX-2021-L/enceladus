import { Link } from '@tanstack/react-router'
import { useQuery } from '@tanstack/react-query'
import {
  CircleDot,
  FileText,
  Lightbulb,
  ListChecks,
  Map as MapIcon,
  Sparkles,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { projectRegistryQueryOptions, resolveProjectFromRecordId } from '../api/projectRegistry'
import { useUiStore } from '../store/uiStore'
import { DOCUMENT_ROUTE_PATH, trackerRoutePath } from '../routes/recordLink'
import type { RecordType } from '../types/records'

// A representative record id per type so the scaffold's nav deep-links resolve.
const NAV: Array<{ type: RecordType; label: string; icon: LucideIcon; sampleId: string }> = [
  { type: 'task', label: 'Tasks', icon: ListChecks, sampleId: 'ENC-TSK-K21' },
  { type: 'issue', label: 'Issues', icon: CircleDot, sampleId: 'ENC-ISS-137' },
  { type: 'feature', label: 'Features', icon: Sparkles, sampleId: 'ENC-FTR-050' },
  { type: 'plan', label: 'Plans', icon: MapIcon, sampleId: 'ENC-PLN-006' },
  { type: 'lesson', label: 'Lessons', icon: Lightbulb, sampleId: 'ENC-LSN-001' },
  { type: 'document', label: 'Documents', icon: FileText, sampleId: 'DOC-E470AC8CE9A8' },
]

function navLinkProps(
  type: RecordType,
  sampleId: string,
  projects: Array<{ project_id: string; prefix: string }>,
) {
  if (type === 'document') {
    return { to: DOCUMENT_ROUTE_PATH as '/document/$id', params: { id: sampleId } }
  }
  const project = resolveProjectFromRecordId(sampleId, projects) ?? 'enceladus'
  return {
    to: trackerRoutePath(type) as '/$project/task/$id',
    params: { project, id: sampleId },
  }
}

export function Sidebar() {
  const open = useUiStore((s) => s.sidebarOpen)
  const selectedRecordId = useUiStore((s) => s.selectedRecordId)
  const selectRecord = useUiStore((s) => s.selectRecord)
  const { data: projects = [] } = useQuery(projectRegistryQueryOptions)

  return (
    <nav
      aria-label="Primary"
      style={{
        width: open ? 232 : 0,
        overflow: 'hidden',
        flexShrink: 0,
        background: 'var(--bg-surface-alt)',
        borderRight: 'var(--border-subtle)',
        transition: 'width var(--dur-slow) var(--ease-orbit)',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      <div style={{ padding: 'var(--space-6) var(--space-5)', minWidth: 232 }}>
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
          Primitives
        </h4>
        <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 'var(--space-1)' }}>
          {NAV.map(({ type, label, icon: Icon, sampleId }) => {
            const active = selectedRecordId === sampleId
            return (
              <li key={type}>
                <Link
                  {...navLinkProps(type, sampleId, projects)}
                  onClick={() => selectRecord(sampleId)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 'var(--space-3)',
                    padding: 'var(--space-2) var(--space-3)',
                    borderRadius: 'var(--radius-sm)',
                    color: active ? 'var(--accent-hover)' : 'var(--fg)',
                    background: active ? 'rgba(61,155,168,0.12)' : 'transparent',
                    textDecoration: 'none',
                    fontSize: 'var(--text-sm)',
                    fontFamily: 'var(--font-body)',
                  }}
                >
                  <Icon size={16} strokeWidth={1.5} />
                  {label}
                </Link>
              </li>
            )
          })}
        </ul>
      </div>
    </nav>
  )
}
