import { useRef } from 'react'
import { Button, Flashbar } from '../design-system'
import { useUiStore } from '../store/uiStore'
import { useFeedConnectionStore } from '../store/feedConnectionStore'
import { useFeedBufferStore } from '../store/feedBufferStore'
import { useRealtimeFeed, useRealtimeFeedEvents } from '../realtime/RealtimeFeedProvider'
import { filterFeedEvents } from '../realtime/feedEventReducer'
import type { RecordType } from '../types/records'

/** ENC-TSK-K24 (B67 AC-11): fixed height so the banner's appear/disappear
 * never shifts the list below it — CLS 0.0 by construction (a reserved
 * slot, not a conditionally-mounted element), not by measurement. */
const NEW_ACTIVITIES_BANNER_HEIGHT = 40

const FILTERABLE: RecordType[] = ['task', 'issue', 'feature', 'plan', 'lesson', 'document']

function phaseLabel(phase: string): string {
  switch (phase) {
    case 'connected':
      return 'Live'
    case 'connecting':
      return 'Connecting…'
    case 'reconnecting':
      return 'Reconnecting…'
    case 'manual_retry':
      return 'Disconnected'
    case 'disconnected':
      return 'Offline (S3 snapshot)'
    default:
      return 'Idle'
  }
}

export function FeedPane({ onClose }: { onClose?: () => void }) {
  const filters = useUiStore((s) => s.filters)
  const toggleFilterType = useUiStore((s) => s.toggleFilterType)

  const phase = useFeedConnectionStore((s) => s.phase)
  const reconnectAttempt = useFeedConnectionStore((s) => s.reconnectAttempt)
  const p50LatencyMs = useFeedConnectionStore((s) => s.p50LatencyMs)
  const p99LatencyMs = useFeedConnectionStore((s) => s.p99LatencyMs)
  const errorMessage = useFeedConnectionStore((s) => s.errorMessage)

  const { isHydrating, isSnapshotError, refetchSnapshot, manualReconnect, mergeBufferedEvents } =
    useRealtimeFeed()
  const events = useRealtimeFeedEvents()
  const bufferedCount = useFeedBufferStore((s) => s.bufferedEvents.length)
  const scrollRef = useRef<HTMLElement>(null)

  const visibleEvents = filterFeedEvents(events, filters.recordTypes)

  const showNewActivities = () => {
    mergeBufferedEvents()
    if (typeof scrollRef.current?.scrollTo === 'function') {
      scrollRef.current.scrollTo({ top: 0, behavior: 'smooth' })
    }
  }

  return (
    <aside
      ref={scrollRef}
      style={{
        width: 260,
        flexShrink: 0,
        borderRight: 'var(--border-subtle)',
        background: 'var(--bg-surface)',
        padding: 'var(--space-5)',
        overflowY: 'auto',
        display: 'flex',
        flexDirection: 'column',
        gap: 'var(--space-4)',
      }}
    >
      <div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 'var(--space-2)', marginBottom: 'var(--space-2)' }}>
          <h4
            style={{
              fontFamily: 'var(--font-heading)',
              fontSize: 'var(--text-xs)',
              fontWeight: 'var(--fw-bold)',
              textTransform: 'uppercase',
              letterSpacing: '0.09em',
              color: 'var(--accent)',
              margin: 0,
            }}
          >
            Feed
          </h4>
          {onClose && (
            <Button variant="link" ariaLabel="Close feed rail" onClick={onClose}>
              Close
            </Button>
          )}
        </div>
        <p
          style={{
            margin: 0,
            fontSize: 'var(--text-xs)',
            color: 'var(--fg-muted)',
            fontFamily: 'var(--font-mono)',
          }}
        >
          {phaseLabel(phase)}
          {reconnectAttempt > 0 ? ` · attempt ${reconnectAttempt}` : ''}
        </p>
        {p50LatencyMs !== null && (
          <p style={{ margin: 'var(--space-1) 0 0', fontSize: 'var(--text-xs)', color: 'var(--fg-muted)' }}>
            WSS P50 {Math.round(p50LatencyMs)}ms
            {p99LatencyMs !== null ? ` · P99 ${Math.round(p99LatencyMs)}ms` : ''}
          </p>
        )}
        {/* ENC-ISS-513 / FND-01: the keystroke/request-page p50/p95 search
            telemetry used to be duplicated here AND on the /feed page
            itself. That block now lives once, on FeedRoute (behind a
            disclosure), since that's the surface actually running the
            search this rail just mirrors. */}
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)' }}>
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

      {(phase === 'manual_retry' || isSnapshotError) && (
        <div role="alert" aria-live="assertive">
          <p style={{ color: 'var(--fg-muted)', fontSize: 'var(--text-sm)', margin: '0 0 var(--space-2)' }}>
            {errorMessage ?? 'Feed snapshot failed to load.'}
          </p>
          <button
            type="button"
            onClick={() => {
              manualReconnect()
              refetchSnapshot()
            }}
            style={{
              fontFamily: 'var(--font-heading)',
              fontSize: 'var(--text-xs)',
              padding: 'var(--space-2) var(--space-3)',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--accent)',
              background: 'rgba(61,155,168,0.12)',
              color: 'var(--accent-hover)',
              cursor: 'pointer',
            }}
          >
            Retry
          </button>
        </div>
      )}

      {/* ENC-TSK-K24 (B67 AC-11): reserved slot, always rendered at a fixed
          height so appearing/disappearing content never shifts the list
          below — CLS 0.0 by construction. */}
      <div
        data-testid="new-activities-banner-slot"
        style={{ height: NEW_ACTIVITIES_BANNER_HEIGHT, flexShrink: 0, overflow: 'hidden' }}
      >
        {bufferedCount > 0 && (
          <Flashbar
            items={[
              {
                id: 'new-activities',
                type: 'info',
                content: (
                  <div data-testid="new-activities-banner" style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                    <span>
                      {bufferedCount} new {bufferedCount === 1 ? 'activity' : 'activities'}
                    </span>
                    <Button variant="link" onClick={showNewActivities}>
                      Show
                    </Button>
                  </div>
                ),
              },
            ]}
          />
        )}
      </div>

      <div style={{ flex: 1, minHeight: 0 }}>
        {isHydrating && visibleEvents.length === 0 && (
          <p style={{ color: 'var(--fg-muted)', fontSize: 'var(--text-sm)' }}>Loading snapshot…</p>
        )}
        {!isHydrating && visibleEvents.length === 0 && (
          <p style={{ color: 'var(--fg-muted)', fontSize: 'var(--text-sm)' }}>
            No feed events yet. S3 snapshot and AppSync WSS will populate this pane.
          </p>
        )}
        <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
          {visibleEvents.slice(0, 30).map((event) => (
            <li
              key={event.eventId}
              style={{
                borderLeft: '2px solid rgba(61,155,168,0.35)',
                paddingLeft: 'var(--space-3)',
              }}
            >
              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 'var(--text-xs)',
                  color: 'var(--accent)',
                }}
              >
                {event.recordId}
              </div>
              <div style={{ fontSize: 'var(--text-sm)', color: 'var(--fg)', lineHeight: 'var(--lh-relaxed)' }}>
                {event.summary}
              </div>
            </li>
          ))}
        </ul>
      </div>
    </aside>
  )
}
