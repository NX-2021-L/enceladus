import { useState, type ReactNode } from 'react'
import { Link } from '@tanstack/react-router'
import { RecordId } from './RecordId'
import { StatusChip } from './StatusChip'
import { Tabs } from '../design-system'
import { recordHrefForType } from '../routes/recordLink'
import type {
  AcceptanceCriterion,
  HistoryEntry,
  RecordType,
  TypedRelationshipEdge,
} from '../types/records'
import { TypedRelationshipSection } from './TypedRelationshipSection'
import { MarkdownContent } from './MarkdownContent'
import './recordDetailHub.css'

export interface HubVital {
  label: string
  value: ReactNode
}

export interface HubAction {
  label: string
  href?: string
  onClick?: () => void
}

/**
 * RecordDetailHub -- the mobile-first Record Details organism (ENC-TSK-M23 /
 * FND-03, cutover-blocking). Mobile base: a focused head (kind + ID + title
 * + StatusChip + a key-value vitals grid) above the fold, a sticky bottom
 * action bar in the thumb zone, and Overview/Neighbors/Worklog/Evidence
 * behind a segmented `Tabs` control (design-system-2) so non-Overview
 * content is only constructed once its tab is opened. Desktop (>= 64rem)
 * projects the same segments into a two-column hub: head+actions become a
 * sticky sidebar, tab content sits alongside it.
 *
 * Read-only surface by design (architect direction, DOC-6EFD5DB32CD8): the
 * built-in action is Copy ID; callers may pass additional link-only actions
 * (e.g. "Open PR") ONLY when the record's own data actually supports them.
 * No governed-mutation trigger (Advance/Escalate) is wired from this page.
 */
export function RecordDetailHub({
  recordId,
  kindLabel,
  title,
  status,
  priority,
  recordType,
  vitals = [],
  overview,
  neighbors,
  worklog,
  evidence,
  actions = [],
}: {
  recordId: string
  kindLabel: string
  title: string
  status?: string
  priority?: string
  recordType?: string
  vitals?: HubVital[]
  overview: ReactNode
  neighbors?: ReactNode
  worklog?: ReactNode
  evidence?: ReactNode
  actions?: HubAction[]
}) {
  const [copied, setCopied] = useState(false)

  const copyId = () => {
    navigator.clipboard
      ?.writeText(recordId)
      .then(() => {
        setCopied(true)
        setTimeout(() => setCopied(false), 1500)
      })
      .catch(() => {
        // Clipboard API unavailable/denied -- the ID is always visible in
        // the head for manual copy, so this is a silent no-op.
      })
  }

  const tabs = [
    { id: 'overview', label: 'Overview', content: overview },
    ...(neighbors ? [{ id: 'neighbors', label: 'Neighbors', content: neighbors }] : []),
    ...(worklog ? [{ id: 'worklog', label: 'Worklog', content: worklog }] : []),
    ...(evidence ? [{ id: 'evidence', label: 'Evidence', content: evidence }] : []),
  ]

  return (
    <div className="ev2-rdh">
      <div className="ev2-rdh__main">
        <header className="ev2-rdh__head">
          <div className="ev2-rdh__kicker">
            <span className="ev2-rdh__kind">{kindLabel}</span>
            <RecordId id={recordId} />
            {status ? (
              <StatusChip status={status} priority={priority} recordType={recordType} />
            ) : null}
          </div>
          <h1 className="ev2-rdh__title">{title}</h1>
          {vitals.length ? (
            <dl className="ev2-rdh__vitals">
              {vitals.map((v) => (
                <div className="ev2-rdh__vital" key={v.label}>
                  <dt className="ev2-rdh__vital-label">{v.label}</dt>
                  <dd className="ev2-rdh__vital-value">{v.value}</dd>
                </div>
              ))}
            </dl>
          ) : null}
          <div className="ev2-rdh__actionbar ev2-rdh__actionbar--inline">
            <ActionButtons copied={copied} onCopy={copyId} actions={actions} />
          </div>
        </header>

        <section className="ev2-rdh__body">
          <Tabs tabs={tabs} />
        </section>
      </div>

      <div
        className="ev2-rdh__actionbar ev2-rdh__actionbar--sticky"
        role="toolbar"
        aria-label="Record actions"
      >
        <ActionButtons copied={copied} onCopy={copyId} actions={actions} />
      </div>
    </div>
  )
}

function ActionButtons({
  copied,
  onCopy,
  actions,
}: {
  copied: boolean
  onCopy: () => void
  actions: HubAction[]
}) {
  return (
    <>
      <button type="button" className="ev2-rdh__action ev2-rdh__action--copy" onClick={onCopy}>
        {copied ? 'Copied' : 'Copy ID'}
      </button>
      {actions.map((a) =>
        a.href ? (
          <a key={a.label} className="ev2-rdh__action" href={a.href} target="_blank" rel="noreferrer">
            {a.label}
          </a>
        ) : (
          <button key={a.label} type="button" className="ev2-rdh__action" onClick={a.onClick}>
            {a.label}
          </button>
        ),
      )}
    </>
  )
}

function inferNeighborType(id: string): RecordType {
  if (id.startsWith('DOC-')) return 'document'
  if (id.includes('-PLN-')) return 'plan'
  if (id.includes('-ISS-')) return 'issue'
  if (id.includes('-FTR-')) return 'feature'
  if (id.includes('-LSN-')) return 'lesson'
  return 'task'
}

/** One labeled group of plain (untyped) related-record IDs, rendered as
 *  navigable rows -- clicking a neighbor goes to THAT record's own details
 *  page (graph navigable), never a modal or inline expansion. */
export function NeighborGroup({
  label,
  ids,
  projectId,
  type,
}: {
  label: string
  ids: string[] | undefined
  projectId: string
  type?: RecordType
}) {
  if (!ids?.length) return null
  return (
    <div className="ev2-rdh__neighbor-group">
      <div className="ev2-rdh__neighbor-label">
        {label} <span className="ev2-rdh__neighbor-count">{ids.length}</span>
      </div>
      <ul className="ev2-rdh__neighbor-list">
        {ids.map((id) => {
          const t = type ?? inferNeighborType(id)
          return (
            <li key={id}>
              <Link
                to={recordHrefForType(t === 'document' ? null : projectId, t, id)}
                className="ev2-rdh__neighbor-link"
              >
                <RecordId id={id} />
              </Link>
            </li>
          )
        })}
      </ul>
    </div>
  )
}

/** Neighbors tab body: plain related-id groups plus the existing typed-edge
 *  graph section (TypedRelationshipSection), when either is present. */
export function NeighborsTab({
  projectId,
  groups,
  typedEdges,
}: {
  projectId: string
  groups: { label: string; ids: string[] | undefined; type?: RecordType }[]
  typedEdges?: TypedRelationshipEdge[]
}) {
  return (
    <div className="ev2-rdh__neighbors">
      {groups.map((g) => (
        <NeighborGroup key={g.label} label={g.label} ids={g.ids} projectId={projectId} type={g.type} />
      ))}
      {typedEdges?.length ? (
        <TypedRelationshipSection projectId={projectId} edges={typedEdges} />
      ) : null}
    </div>
  )
}

/** Worklog tab body: the record's history[], most recent first. Entries
 *  render through MarkdownContent (ENC-TSK-M32) -- worklog descriptions
 *  routinely carry inline record IDs (PR merges, backport notes) that
 *  should link like anywhere else. */
export function WorklogTab({
  history,
  projectId,
}: {
  history: HistoryEntry[] | undefined
  projectId?: string
}) {
  if (!history?.length) return null
  return (
    <ul className="ev2-rdh__worklog-list">
      {[...history].reverse().map((h, i) => (
        <li className="ev2-rdh__worklog-item" key={`${h.timestamp}-${i}`}>
          <div className="ev2-rdh__worklog-meta">
            <span className="ev2-rdh__worklog-ts">{h.timestamp}</span>
            <StatusChip status={h.status} />
          </div>
          <MarkdownContent text={h.description} projectId={projectId} className="ev2-rdh__worklog-desc" />
        </li>
      ))}
    </ul>
  )
}

/** Evidence tab body: acceptance-criteria stamps (governed AC evidence),
 *  rendered through MarkdownContent (ENC-TSK-M32) so evidence text -- which
 *  often embeds record IDs, hashes, or run URLs -- wraps instead of
 *  overflowing and links inline IDs like everywhere else. */
export function EvidenceTab({
  criteria,
  projectId,
}: {
  criteria: AcceptanceCriterion[] | undefined
  projectId?: string
}) {
  if (!criteria?.length) return null
  return (
    <ul className="ev2-rdh__evidence-list">
      {criteria.map((c, i) => (
        <li className="ev2-rdh__evidence-item" key={i}>
          <span className={`ev2-rdh__evidence-badge${c.evidence_acceptance ? ' is-accepted' : ''}`}>
            {c.evidence_acceptance ? 'Accepted' : 'Pending'}
          </span>
          <div className="ev2-rdh__evidence-body">
            <MarkdownContent text={c.description} projectId={projectId} className="ev2-rdh__evidence-desc" />
            {c.evidence ? (
              <MarkdownContent text={c.evidence} projectId={projectId} className="ev2-rdh__evidence-proof" />
            ) : null}
          </div>
        </li>
      ))}
    </ul>
  )
}
