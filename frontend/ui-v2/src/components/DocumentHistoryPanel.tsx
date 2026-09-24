import { useEffect, useState } from 'react'
import {
  fetchDocumentAtVersion,
  fetchDocumentDiff,
  fetchDocumentHistory,
  isRejectedEvent,
  sha256Hex,
  type DocumentHistoryEvent,
} from '../api/documentHistory'
import { MarkdownContent } from './MarkdownContent'
import './documentHistory.css'

/**
 * ENC-TSK-P81 (FR-B5-4, AC-1/AC-2) — the document detail "History" tab.
 * Lazily imported (see primitives/DocumentPrimitive.tsx) so this module and
 * its sub-components ship as their own chunk, not inside the already-large
 * `document` primitive chunk.
 *
 * Codes against the documents.history / documents.get(at_version) /
 * documents.diff contract landing with ENC-TSK-P72 (in flight) — component
 * tests mock fetch directly (no live backend yet).
 */

function formatTs(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    second: '2-digit',
  })
}

function anchorLabel(event: DocumentHistoryEvent): string {
  if (event.anchor?.heading_path?.length) return event.anchor.heading_path.join(' / ')
  if (event.anchor?.block_id) return event.anchor.block_id
  return '—'
}

export function DocumentHistoryEventRow({
  event,
  selected,
  onSelect,
}: {
  event: DocumentHistoryEvent
  selected: boolean
  onSelect: () => void
}) {
  const rejected = isRejectedEvent(event)
  const classes = [
    'ev2-history__event',
    rejected ? 'ev2-history__event--rejected' : '',
    selected ? 'ev2-history__event--selected' : '',
  ]
    .filter(Boolean)
    .join(' ')

  return (
    <button
      type="button"
      onClick={onSelect}
      aria-pressed={selected}
      data-testid={`history-event-${event.event_id}`}
      className={classes}
    >
      <span className="ev2-history__event-op">{event.op}</span>
      <span className="ev2-history__event-actor">{event.actor}</span>
      <span className="ev2-history__event-surface">{event.surface}</span>
      <span className="ev2-history__event-anchor">{anchorLabel(event)}</span>
      <span className="ev2-history__event-version">
        v{event.before_version} &rarr; v{event.after_version}
      </span>
      <span className="ev2-history__event-ts">{formatTs(event.ts)}</span>
      {rejected && (
        <span className="ev2-history__event-badge">
          Rejected{event.rejection_code ? ` · ${event.rejection_code}` : ''}
        </span>
      )}
    </button>
  )
}

type RewindState =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'ready'; content: string; version: number; verified: boolean }

export function DocumentRewindPane({
  documentId,
  projectId,
  event,
}: {
  documentId: string
  projectId: string
  event: DocumentHistoryEvent
}) {
  const [state, setState] = useState<RewindState>({ status: 'loading' })

  useEffect(() => {
    let cancelled = false
    // Reset to 'loading' synchronously when the selected event changes (the
    // async fetch below then transitions to 'ready'/'error' from its own
    // then/catch, not synchronously in the effect body).
    // eslint-disable-next-line react-hooks/set-state-in-effect -- deliberate loading-state reset on selection change, not a derivable/external-sync value
    setState({ status: 'loading' })
    ;(async () => {
      try {
        const resp = await fetchDocumentAtVersion(documentId, projectId, event.after_version)
        const computed = await sha256Hex(resp.content)
        const verified = resp.content_hash === event.after_hash && computed === resp.content_hash
        if (!cancelled) setState({ status: 'ready', content: resp.content, version: resp.version, verified })
      } catch (err) {
        if (!cancelled) {
          setState({ status: 'error', message: err instanceof Error ? err.message : 'Failed to load this version.' })
        }
      }
    })()
    return () => {
      cancelled = true
    }
  }, [documentId, projectId, event.event_id, event.after_version, event.after_hash])

  if (state.status === 'loading') {
    return <p className="ev2-history__rewind-status">Loading version {event.after_version}&hellip;</p>
  }
  if (state.status === 'error') {
    return (
      <p className="ev2-history__rewind-status ev2-history__rewind-status--error" data-testid="document-rewind-error">
        {state.message}
      </p>
    )
  }

  return (
    <div className="ev2-history__rewind" data-testid="document-rewind-pane">
      <div className="ev2-history__rewind-head">
        <span className="ev2-history__rewind-pill">reconstructed</span>
        <span
          className={`ev2-history__rewind-badge ${
            state.verified ? 'ev2-history__rewind-badge--verified' : 'ev2-history__rewind-badge--mismatch'
          }`}
        >
          {state.verified ? 'hash verified' : 'hash mismatch'}
        </span>
        <span className="ev2-history__rewind-version">v{state.version}</span>
      </div>
      <MarkdownContent text={state.content} projectId={projectId} />
    </div>
  )
}

type DiffState =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'ready'; diff: string; truncated?: boolean }

export function DocumentDiffPane({
  documentId,
  projectId,
  fromVersion,
  toVersion,
}: {
  documentId: string
  projectId: string
  fromVersion: number
  toVersion: number
}) {
  const [state, setState] = useState<DiffState>({ status: 'loading' })

  useEffect(() => {
    let cancelled = false
    // eslint-disable-next-line react-hooks/set-state-in-effect -- deliberate loading-state reset on version-pair change, not a derivable/external-sync value
    setState({ status: 'loading' })
    fetchDocumentDiff(documentId, projectId, fromVersion, toVersion)
      .then((resp) => {
        if (!cancelled) setState({ status: 'ready', diff: resp.diff, truncated: resp.truncated })
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setState({ status: 'error', message: err instanceof Error ? err.message : 'Failed to load diff.' })
        }
      })
    return () => {
      cancelled = true
    }
  }, [documentId, projectId, fromVersion, toVersion])

  if (state.status === 'loading') {
    return (
      <p className="ev2-history__diff-status">
        Loading diff v{fromVersion} &rarr; v{toVersion}&hellip;
      </p>
    )
  }
  if (state.status === 'error') {
    return (
      <p className="ev2-history__diff-status ev2-history__diff-status--error" data-testid="document-diff-error">
        {state.message}
      </p>
    )
  }

  const lines = state.diff.split('\n')

  return (
    <div className="ev2-history__diff" data-testid="document-diff-pane">
      <div className="ev2-history__diff-head">
        <span>
          v{fromVersion} &rarr; v{toVersion}
        </span>
        {state.truncated && <span className="ev2-history__diff-truncated">truncated</span>}
      </div>
      <pre className="ev2-history__diff-body">
        {lines.map((line, i) => {
          const isAdd = line.startsWith('+') && !line.startsWith('+++')
          const isDel = line.startsWith('-') && !line.startsWith('---')
          const cls = isAdd
            ? 'ev2-history__diff-line ev2-history__diff-line--add'
            : isDel
              ? 'ev2-history__diff-line ev2-history__diff-line--del'
              : 'ev2-history__diff-line'
          return (
            <div key={i} className={cls}>
              {line || ' '}
            </div>
          )
        })}
      </pre>
    </div>
  )
}

const MAX_SELECTED = 2

export function DocumentHistoryPanel({ documentId, projectId }: { documentId: string; projectId: string }) {
  const [events, setEvents] = useState<DocumentHistoryEvent[]>([])
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [actorFilter, setActorFilter] = useState('')
  const [anchorFilter, setAnchorFilter] = useState('')
  const [selected, setSelected] = useState<string[]>([])

  async function loadPage(cursor?: string) {
    setLoading(true)
    setError(null)
    try {
      const page = await fetchDocumentHistory(documentId, projectId, { cursor, pageSize: 50 })
      // AC-1: the API orders events ts-ascending within a page; the UI shows
      // newest first, so each page is reversed before being appended.
      setEvents((prev) => [...prev, ...[...page.events].reverse()])
      setNextCursor(page.next_cursor)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load document history.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- deliberate list reset on documentId/projectId change, not a derivable/external-sync value
    setEvents([])
    setNextCursor(null)
    setSelected([])
    loadPage(undefined)
    // eslint-disable-next-line react-hooks/exhaustive-deps -- loadPage is stable per documentId/projectId pair
  }, [documentId, projectId])

  function toggleSelect(eventId: string) {
    setSelected((prev) => {
      if (prev.includes(eventId)) return prev.filter((id) => id !== eventId)
      if (prev.length >= MAX_SELECTED) return [...prev.slice(1), eventId]
      return [...prev, eventId]
    })
  }

  const anchorOptions = Array.from(new Set(events.map((e) => anchorLabel(e)))).filter((label) => label !== '—')

  const filteredEvents = events.filter((event) => {
    const actorOk = !actorFilter.trim() || event.actor.toLowerCase().includes(actorFilter.trim().toLowerCase())
    const anchorOk = !anchorFilter || anchorLabel(event) === anchorFilter
    return actorOk && anchorOk
  })

  const selectedEvents = events.filter((e) => selected.includes(e.event_id))
  const rewindEvent = selectedEvents.length === 1 ? selectedEvents[0] : null
  const diffEvents =
    selectedEvents.length === 2
      ? [...selectedEvents].sort((a, b) => a.after_version - b.after_version)
      : null

  return (
    <div className="ev2-history" data-testid="document-history-panel">
      <div className="ev2-history__toolbar">
        <label className="ev2-history__filter">
          <span className="ev2-history__filter-label">Actor</span>
          <input
            type="text"
            value={actorFilter}
            onChange={(e) => setActorFilter(e.target.value)}
            placeholder="Filter by actor"
            aria-label="Filter by actor"
            className="ev2-history__filter-input"
          />
        </label>
        <label className="ev2-history__filter">
          <span className="ev2-history__filter-label">Anchor</span>
          <select
            value={anchorFilter}
            onChange={(e) => setAnchorFilter(e.target.value)}
            aria-label="Filter by anchor"
            className="ev2-history__filter-select"
          >
            <option value="">All anchors</option>
            {anchorOptions.map((label) => (
              <option key={label} value={label}>
                {label}
              </option>
            ))}
          </select>
        </label>
      </div>

      {error && (
        <p className="ev2-history__status ev2-history__status--error" data-testid="document-history-error">
          {error}
        </p>
      )}

      {!error && events.length === 0 && !loading && <p className="ev2-history__status">No history yet.</p>}

      {!error && events.length > 0 && filteredEvents.length === 0 && (
        <p className="ev2-history__status">No events match the current filters.</p>
      )}

      <div className="ev2-history__list">
        {filteredEvents.map((event) => (
          <DocumentHistoryEventRow
            key={event.event_id}
            event={event}
            selected={selected.includes(event.event_id)}
            onSelect={() => toggleSelect(event.event_id)}
          />
        ))}
      </div>

      {loading && <p className="ev2-history__status">Loading&hellip;</p>}

      {nextCursor && !loading && (
        <button type="button" onClick={() => loadPage(nextCursor)} className="ev2-history__load-more">
          Load older
        </button>
      )}

      {rewindEvent && (
        <DocumentRewindPane documentId={documentId} projectId={projectId} event={rewindEvent} />
      )}

      {diffEvents && (
        <DocumentDiffPane
          documentId={documentId}
          projectId={projectId}
          fromVersion={diffEvents[0].after_version}
          toVersion={diffEvents[1].after_version}
        />
      )}
    </div>
  )
}
