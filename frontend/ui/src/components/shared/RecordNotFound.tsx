/**
 * RecordNotFound — explicit 404 state for the direct-API fallback path
 * (ENC-FTR-073 Phase 2c / ENC-TSK-D96).
 *
 * Replaces the ad-hoc `<ErrorState message="Plan X not found">` pattern with
 * a typed, accessible component. Pure presentational — no hooks, no data
 * coupling. Phase 3 wires it into each detail page from the hook's return
 * values.
 *
 * Props:
 *   - recordType: task/issue/feature/plan/lesson/document — surfaces in the
 *     detail copy.
 *   - recordId: the attempted ID. Required so the user can verify they pasted
 *     the right URL.
 *   - projectId: optional; not currently rendered but reserved for future
 *     navigation.
 */

import { Link } from 'react-router-dom'
import type { RecordType } from '../../lib/recordNormalizers'

interface Props {
  recordType: RecordType
  recordId: string
  projectId?: string
}

const TYPE_LABEL: Record<RecordType, string> = {
  task: 'task',
  issue: 'issue',
  feature: 'feature',
  plan: 'plan',
  lesson: 'lesson',
  document: 'document',
}

const BACK_PATH: Record<RecordType, string> = {
  task: '/tasks',
  issue: '/issues',
  feature: '/features',
  plan: '/plans',
  lesson: '/lessons',
  document: '/documents',
}

export function RecordNotFound({ recordType, recordId, projectId }: Props) {
  const label = TYPE_LABEL[recordType]
  const backPath = BACK_PATH[recordType] ?? '/'
  return (
    <div
      role="status"
      aria-live="polite"
      className="flex flex-col items-center justify-center py-16 px-4 text-center"
    >
      <svg
        className="w-12 h-12 text-amber-400 mb-3"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
        strokeWidth={1.5}
        aria-hidden="true"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
        />
      </svg>
      <h2 className="text-slate-200 text-base font-semibold">Record not found</h2>
      <p className="text-slate-400 text-sm mt-1">
        No {label} with ID <span className="font-mono text-slate-300">{recordId}</span>{' '}
        {projectId ? (
          <>
            exists in project <span className="font-mono text-slate-300">{projectId}</span>.
          </>
        ) : (
          <>exists.</>
        )}
      </p>
      <Link
        to={backPath}
        className="mt-4 text-xs text-blue-400 hover:text-blue-300 hover:underline"
      >
        Back to {label}s
      </Link>
    </div>
  )
}
