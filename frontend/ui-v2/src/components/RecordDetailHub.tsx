import { useState, type ReactNode } from 'react'
import { Link } from '@tanstack/react-router'
import { RecordId } from './RecordId'
import { StatusChip } from './StatusChip'
import { Modal, Tabs } from '../design-system'
import { recordHrefForType } from '../routes/recordLink'
import type {
  AcceptanceCriterion,
  HistoryEntry,
  IssueEvidence,
  RecordType,
  TypedRelationshipEdge,
} from '../types/records'
import { TypedRelationshipSection } from './TypedRelationshipSection'
import { MarkdownContent } from './MarkdownContent'
import { useRecordMutation } from '../hooks/useRecordMutation'
import { computePrimaryActions, type TransitionAction } from '../utils/transitionArcs'
import './recordDetailHub.css'

export interface HubVital {
  label: string
  value: ReactNode
}

/**
 * Drives the state-aware primary action + Note button (ENC-TSK-M33 AC-2/3).
 * Every field here comes straight off the tracker record -- callers (the
 * Task/Issue/Feature/Plan primitives) supply it alongside their own
 * type-specific `vitals`/`overview`/tab content; RecordDetailHub owns the
 * actual mutation wiring so it lives in exactly one place.
 */
export interface RecordMutationContext {
  projectId: string
  recordType: 'task' | 'issue' | 'feature' | 'plan'
  recordId: string
  status: string
  transitionType?: string | null
  checkedOut: boolean
  syncVersion?: number
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
 * ENC-TSK-M33 (v3 action parity, HARD cutover gate) lifted the read-only
 * restriction noted in the prior revision of this comment
 * (DOC-6EFD5DB32CD8): Copy ID remains built in, and this component now also
 * owns the state-aware primary transition button (Check In / advance /
 * revert / Submit + Close) and the Note button, both executing through the
 * SAME governed `useRecordMutation` write path the rest of the PWA uses
 * (tracker PATCH -> ENC-ISS-092 user_initiated bypass for forward task
 * writes, transition_evidence.revert_reason for backward writes on any
 * type) -- never a new write surface. Callers still pass `actions` for
 * simple link-only controls (GitHub link) and `chips` for the DOC-B6B52E3BB9BB
 * §7 chip row.
 */
export function RecordDetailHub({
  recordId,
  kindLabel,
  title,
  status,
  priority,
  recordType,
  chips,
  vitals = [],
  overview,
  content,
  neighbors,
  worklog,
  evidence,
  actions = [],
  mutation,
}: {
  recordId: string
  kindLabel: string
  title: string
  status?: string
  priority?: string
  recordType?: string
  /** Extra chips (severity/category/active-session/checkout/component)
   *  rendered after the built-in StatusChip -- see components/ChipRow.tsx. */
  chips?: ReactNode
  vitals?: HubVital[]
  overview: ReactNode
  /** Optional "Content" tab (Docs.dc.html) — full document body, rendered
   *  between Overview and Neighbors. ENC-TSK-M34. */
  content?: ReactNode
  neighbors?: ReactNode
  worklog?: ReactNode
  evidence?: ReactNode
  actions?: HubAction[]
  /** ENC-TSK-M33 -- when present, renders the state-aware primary
   *  transition button(s) + the Note button, wired to real governed writes. */
  mutation?: RecordMutationContext
}) {
  const [copied, setCopied] = useState(false)
  const [noteOpen, setNoteOpen] = useState(false)
  const [noteText, setNoteText] = useState('')
  const [transition, setTransition] = useState<TransitionAction | null>(null)
  const [transitionNote, setTransitionNote] = useState('')
  const [actionError, setActionError] = useState<string | null>(null)
  const [actionSuccess, setActionSuccess] = useState<string | null>(null)

  const recordMutation = useRecordMutation()

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

  const primaryActions = mutation
    ? computePrimaryActions({
        recordType: mutation.recordType,
        status: mutation.status,
        transitionType: mutation.transitionType,
        checkedOut: mutation.checkedOut,
      })
    : []

  function flashSuccess(message: string) {
    setActionSuccess(message)
    setTimeout(() => setActionSuccess(null), 3000)
  }

  function runCheckIn() {
    if (!mutation) return
    setActionError(null)
    recordMutation.mutate(
      {
        projectId: mutation.projectId,
        recordType: mutation.recordType,
        recordId: mutation.recordId,
        action: 'release',
      },
      {
        onSuccess: () => flashSuccess('Checked in.'),
        onError: (err) => setActionError(err.message || 'Check-in failed.'),
      },
    )
  }

  function openTransition(action: TransitionAction) {
    setTransitionNote('')
    setActionError(null)
    setTransition(action)
  }

  function submitTransition(closeImmediately: boolean) {
    if (!mutation || !transition?.targetStatus) return
    if (!transitionNote.trim()) return
    const targetStatus = closeImmediately ? 'closed' : transition.targetStatus
    const transitionEvidence =
      transition.kind === 'revert'
        ? { revert_reason: transitionNote }
        : { user_initiated: true, user_note: transitionNote }

    // Two-step submit (mirrors the legacy PWA's LifecycleActions.tsx): first
    // land the note as an immediate worklog entry, then apply the status
    // write with the evidence stamped for audit.
    recordMutation.mutate(
      {
        projectId: mutation.projectId,
        recordType: mutation.recordType,
        recordId: mutation.recordId,
        action: 'worklog',
        note: transitionNote,
        syncVersion: mutation.syncVersion,
      },
      {
        onSuccess: () => {
          recordMutation.mutate(
            {
              projectId: mutation.projectId,
              recordType: mutation.recordType,
              recordId: mutation.recordId,
              action: 'set_field',
              field: 'status',
              value: targetStatus,
              transitionEvidence,
              syncVersion: mutation.syncVersion,
            },
            {
              onSuccess: () => {
                setTransition(null)
                setTransitionNote('')
                flashSuccess(`Status changed to ${targetStatus}.`)
              },
              onError: (err) => setActionError(err.message || 'Status change failed.'),
            },
          )
        },
        onError: (err) => setActionError(err.message || 'Note submission failed.'),
      },
    )
  }

  function submitNoteOnly() {
    if (!mutation || !noteText.trim()) return
    setActionError(null)
    recordMutation.mutate(
      {
        projectId: mutation.projectId,
        recordType: mutation.recordType,
        recordId: mutation.recordId,
        action: 'worklog',
        note: noteText,
        syncVersion: mutation.syncVersion,
      },
      {
        onSuccess: () => {
          setNoteOpen(false)
          setNoteText('')
          flashSuccess('Note added to worklog.')
        },
        onError: (err) => setActionError(err.message || 'Note failed.'),
      },
    )
  }

  const tabs = [
    { id: 'overview', label: 'Overview', content: overview },
    ...(content !== undefined ? [{ id: 'content', label: 'Content', content }] : []),
    ...(neighbors ? [{ id: 'neighbors', label: 'Neighbors', content: neighbors }] : []),
    ...(worklog ? [{ id: 'worklog', label: 'Worklog', content: worklog }] : []),
    ...(evidence ? [{ id: 'evidence', label: 'Evidence', content: evidence }] : []),
  ]

  function renderActionButtons() {
    return (
      <ActionButtons
        copied={copied}
        onCopy={copyId}
        actions={actions}
        primaryActions={primaryActions}
        mutating={recordMutation.isPending}
        onCheckIn={runCheckIn}
        onTransitionClick={openTransition}
        onNoteClick={() => {
          setNoteText('')
          setActionError(null)
          setNoteOpen(true)
        }}
      />
    )
  }

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
            {chips}
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
          {actionSuccess || actionError ? (
            <p className={`ev2-rdh__action-feedback${actionError ? ' is-error' : ''}`}>
              {actionError ?? actionSuccess}
            </p>
          ) : null}
          <div className="ev2-rdh__actionbar ev2-rdh__actionbar--inline">
            {renderActionButtons()}
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
        {renderActionButtons()}
      </div>

      {/* Note bottom sheet (ENC-TSK-M33 AC-3) -- appends an immediate,
          visible worklog entry through the governed write path. */}
      <Modal
        visible={noteOpen}
        header="Add Note"
        recordId={recordId}
        onDismiss={() => {
          setNoteOpen(false)
          setNoteText('')
        }}
        footer={
          <>
            <button
              type="button"
              className="ev2-rdh__action ev2-rdh__modal-cancel"
              onClick={() => {
                setNoteOpen(false)
                setNoteText('')
              }}
            >
              Cancel
            </button>
            <button
              type="button"
              className="ev2-rdh__action ev2-rdh__modal-submit"
              disabled={!noteText.trim() || recordMutation.isPending}
              onClick={submitNoteOnly}
            >
              {recordMutation.isPending ? 'Saving…' : 'Submit'}
            </button>
          </>
        }
      >
        <textarea
          className="ev2-rdh__note-textarea"
          rows={5}
          maxLength={2000}
          value={noteText}
          onChange={(e) => setNoteText(e.target.value)}
          placeholder="Describe what changed, what's needed, or any context…"
          autoFocus
        />
        {actionError ? <p className="ev2-rdh__action-feedback is-error">{actionError}</p> : null}
      </Modal>

      {/* Transition bottom sheet (ENC-TSK-M33 AC-2) -- advance/revert require
          a note (ENC-ISS-092 user_note / transition_evidence.revert_reason),
          matching the legacy PWA's LifecycleActions modal. Tasks only get the
          extra "Submit + Close" terminal shortcut. */}
      <Modal
        visible={transition !== null}
        header={transition?.kind === 'revert' ? 'Revert status' : 'Advance status'}
        recordId={recordId}
        onDismiss={() => {
          setTransition(null)
          setTransitionNote('')
        }}
        footer={
          <>
            <button
              type="button"
              className="ev2-rdh__action ev2-rdh__modal-cancel"
              onClick={() => {
                setTransition(null)
                setTransitionNote('')
              }}
            >
              Cancel
            </button>
            {transition?.allowSubmitClose ? (
              <button
                type="button"
                className="ev2-rdh__action ev2-rdh__modal-submit ev2-rdh__modal-submit--danger"
                disabled={!transitionNote.trim() || recordMutation.isPending}
                title="Skip all remaining stages and close this task immediately"
                onClick={() => submitTransition(true)}
              >
                {recordMutation.isPending ? 'Saving…' : 'Submit + Close'}
              </button>
            ) : null}
            <button
              type="button"
              className="ev2-rdh__action ev2-rdh__modal-submit"
              disabled={!transitionNote.trim() || recordMutation.isPending}
              onClick={() => submitTransition(false)}
            >
              {recordMutation.isPending ? 'Saving…' : 'Submit'}
            </button>
          </>
        }
      >
        <p className="ev2-rdh__modal-hint">
          {transition?.kind === 'revert'
            ? 'Add a note explaining why this is being reverted.'
            : 'Add a note explaining why this is advancing.'}
        </p>
        <textarea
          className="ev2-rdh__note-textarea"
          rows={5}
          maxLength={2000}
          value={transitionNote}
          onChange={(e) => setTransitionNote(e.target.value)}
          placeholder={
            transition?.kind === 'revert' ? 'Why is this being reverted?' : 'Why is this moving forward?'
          }
          autoFocus
        />
        {actionError ? <p className="ev2-rdh__action-feedback is-error">{actionError}</p> : null}
      </Modal>
    </div>
  )
}

function ActionButtons({
  copied,
  onCopy,
  actions,
  primaryActions,
  mutating,
  onCheckIn,
  onTransitionClick,
  onNoteClick,
}: {
  copied: boolean
  onCopy: () => void
  actions: HubAction[]
  primaryActions: TransitionAction[]
  mutating: boolean
  onCheckIn: () => void
  onTransitionClick: (action: TransitionAction) => void
  onNoteClick: () => void
}) {
  return (
    <>
      <button type="button" className="ev2-rdh__action ev2-rdh__action--copy" onClick={onCopy}>
        {copied ? 'Copied' : 'Copy ID'}
      </button>
      {primaryActions.map((pa) => {
        if (pa.kind === 'check-in') {
          return (
            <button
              key="check-in"
              type="button"
              className="ev2-rdh__action ev2-rdh__action--checkin"
              disabled={mutating}
              onClick={onCheckIn}
            >
              {pa.label}
            </button>
          )
        }
        if (pa.disabled) {
          return (
            <button
              key={`${pa.kind}-disabled`}
              type="button"
              className="ev2-rdh__action"
              disabled
              title={pa.disabledReason}
              aria-label={`${pa.label} -- ${pa.disabledReason ?? 'unavailable'}`}
            >
              {pa.label}
            </button>
          )
        }
        return (
          <button
            key={`${pa.kind}-${pa.targetStatus}`}
            type="button"
            className="ev2-rdh__action"
            disabled={mutating}
            onClick={() => onTransitionClick(pa)}
          >
            {pa.label}
          </button>
        )
      })}
      <button type="button" className="ev2-rdh__action ev2-rdh__action--note" onClick={onNoteClick}>
        ✏ Note
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

/** Evidence tab body: ACCEPTANCE CRITERIA checklist (task/feature, DOC-
 *  B6B52E3BB9BB §7) -- a ●/○ accept-state circle per AC (● = accepted, ○ =
 *  evidence not yet accepted, matching the v3 direct visual capture verbatim
 *  rather than a text "Accepted"/"Pending" badge), rendered through
 *  MarkdownContent (ENC-TSK-M32) so evidence text -- which often embeds
 *  record IDs, hashes, or run URLs -- wraps instead of overflowing and links
 *  inline IDs like everywhere else. */
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
          <span
            className={`ev2-rdh__evidence-badge${c.evidence_acceptance ? ' is-accepted' : ''}`}
            role="img"
            aria-label={c.evidence_acceptance ? 'Accepted' : 'Pending'}
            title={c.evidence_acceptance ? 'Accepted' : 'Pending'}
          >
            {c.evidence_acceptance ? '●' : '○'}
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

/** EVIDENCE tab body for issues (DOC-B6B52E3BB9BB §7): each entry is a
 *  description plus its `steps_to_duplicate` repro list -- a different
 *  shape than the AC evidence stamps above (no evidence_acceptance state),
 *  so it gets its own renderer rather than overloading EvidenceTab. */
export function IssueEvidenceTab({
  entries,
  projectId,
}: {
  entries: IssueEvidence[] | undefined
  projectId?: string
}) {
  if (!entries?.length) return null
  return (
    <ul className="ev2-rdh__evidence-list">
      {entries.map((e, i) => (
        <li className="ev2-rdh__evidence-item" key={i}>
          <div className="ev2-rdh__evidence-body">
            <MarkdownContent text={e.description} projectId={projectId} className="ev2-rdh__evidence-desc" />
            {e.steps_to_duplicate?.length ? (
              <ol className="ev2-rdh__evidence-steps">
                {e.steps_to_duplicate.map((step, j) => (
                  <li key={j}>{step}</li>
                ))}
              </ol>
            ) : null}
          </div>
        </li>
      ))}
    </ul>
  )
}
