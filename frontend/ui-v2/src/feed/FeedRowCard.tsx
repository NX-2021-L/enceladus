import { resolveProjectFromRecordId } from '../api/projectRegistry'
import type { ProjectSummary } from '../api/projects'
import { Badge } from '../components/Badge'
import { RecordCard } from '../components/RecordCard'
import { formatRelativeTime } from '../format/relativeTime'
import { documentHref, recordHrefForType } from '../routes/recordLink'
import { feedRowAccent, priorityBadgeColor, sessionStateBadge } from '../search/feedRowPresentation'
import type { SearchResultHit } from '../types/search'
import { SignalReadout } from '@io-kit/search/react'
import type { SignalAvailability, SignalEvidence } from '@io-kit/search'

export interface FeedRowContext {
  projects: ProjectSummary[]
  isWide: boolean
  selectedHit: SearchResultHit | null
  /** Wide viewports select in place (no navigation). */
  onSelect(hit: SearchResultHit): void
  /** Narrow viewports link to the record page; called before leaving so the return search is persisted. */
  onLeave(): void
  /** Per-row hybrid evidence (signal -> rank) and the signal states to render it against. */
  evidenceFor(recordId: string): SignalEvidence[] | undefined
  availability?: SignalAvailability
}

/**
 * ENC-TSK-M35 / DVP-TSK-921 / DVP-TSK-931: the one feed-row rendering, shared by /feed and /docs (kit
 * CollectionSearch renderRow) so both surfaces emit the same card markup. Plain function, not a
 * component: the DOM must stay exactly what LegacyFeedRoute always produced.
 */
export function renderFeedRow(hit: SearchResultHit, cx: FeedRowContext) {
  const project = hit.projectId || resolveProjectFromRecordId(hit.recordId, cx.projects) || 'enceladus'
  const href =
    hit.recordType === 'document' ? documentHref(hit.recordId) : recordHrefForType(project, hit.recordType, hit.recordId)
  const cci = sessionStateBadge(hit.checkoutState)
  const { isWide, selectedHit } = cx

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
  const evidence = cx.evidenceFor(hit.recordId)
  // DVP-TSK-A12 (io): no per-row action under a card; only the hybrid evidence chips remain.
  if (!evidence || !cx.availability) return card
  return (
    <div key={hit.recordId} className="feed-route__row-wrap">
      {card}
      <SignalReadout evidence={evidence} availability={cx.availability} mode="chips" />
    </div>
  )
}
