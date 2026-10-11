import { resolveProjectFromRecordId } from '../api/projectRegistry'
import type { ProjectSummary } from '../api/projects'
import { Badge } from '../components/Badge'
import { RecordCard } from '../components/RecordCard'
import { formatRelativeTime } from '../format/relativeTime'
import { documentHref, recordHrefForType } from '../routes/recordLink'
import { feedRowAccent, priorityBadgeColor, sessionStateBadge } from '../search/feedRowPresentation'
import type { useTieredSearch } from '../search/useTieredSearch'
import type { SearchResultHit } from '../types/search'
import { SignalReadout } from '@io-kit/search/react'

export type PinState = 'pending' | 'done' | 'error'

export interface FeedRowContext {
  projects: ProjectSummary[]
  isWide: boolean
  selectedHit: SearchResultHit | null
  /** Wide viewports select in place (no navigation). */
  onSelect(hit: SearchResultHit): void
  /** Narrow viewports link to the record page; called before leaving so the return search is persisted. */
  onLeave(): void
  tiered: Pick<ReturnType<typeof useTieredSearch>, 'evidenceById' | 'availability'>
  pins: Record<string, PinState>
  onPin(sourceId: string, targetId: string): void
}

/**
 * ENC-TSK-M35 / DVP-TSK-921 / DVP-TSK-931: the one feed-row rendering, shared by the legacy list and the
 * @io-kit/feed panel (renderCard slot) so both engines emit the same card markup. Plain function, not a
 * component: the DOM must stay exactly what LegacyFeedRoute always produced.
 */
export function renderFeedRow(hit: SearchResultHit, cx: FeedRowContext) {
  const project = hit.projectId || resolveProjectFromRecordId(hit.recordId, cx.projects) || 'enceladus'
  const href =
    hit.recordType === 'document' ? documentHref(hit.recordId) : recordHrefForType(project, hit.recordType, hit.recordId)
  const cci = sessionStateBadge(hit.checkoutState)
  const { isWide, selectedHit, pins } = cx

  const card = (
    <RecordCard
      key={hit.recordId}
      recordId={hit.recordId}
      recordType={hit.recordType}
      title={hit.title}
      status={hit.status}
      priority={hit.priority}
      variant="feed"
      projectLabel={project}
      timestamp={formatRelativeTime(hit.updatedAt) ?? undefined}
      accentColor={feedRowAccent(hit)}
      badges={
        <>
          {hit.priority ? <Badge color={priorityBadgeColor(hit.priority)}>{hit.priority}</Badge> : null}
          {cci ? <Badge color={cci.color}>{cci.label}</Badge> : null}
        </>
      }
      {...(isWide
        ? { selected: selectedHit?.recordId === hit.recordId, onSelect: () => cx.onSelect(hit) }
        : { href, onSelect: () => cx.onLeave() })}
    />
  )
  const evidence = cx.tiered.evidenceById.get(hit.recordId)
  const canPin =
    isWide &&
    selectedHit &&
    selectedHit.recordId !== hit.recordId &&
    (hit.recordType === 'task' || hit.recordType === 'issue' || hit.recordType === 'feature')
  if (!evidence && !canPin) return card
  return (
    <div key={hit.recordId} className="feed-route__row-wrap">
      {card}
      <div className="feed-route__row-extras">
        {evidence && cx.tiered.availability ? (
          <SignalReadout evidence={evidence} availability={cx.tiered.availability} mode="chips" />
        ) : null}
        {canPin ? (
          <button
            type="button"
            className="feed-route__pin"
            disabled={pins[hit.recordId] === 'pending' || pins[hit.recordId] === 'done'}
            onClick={() => cx.onPin(selectedHit.recordId, hit.recordId)}
            aria-label={`Pin ${hit.recordId} as related to ${selectedHit.recordId}`}
          >
            {pins[hit.recordId] === 'done' ? 'Pinned' : pins[hit.recordId] === 'error' ? 'Pin failed - retry' : 'Pin as related'}
          </button>
        ) : null}
      </div>
    </div>
  )
}
