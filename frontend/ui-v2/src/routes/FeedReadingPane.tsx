import { Container, Header, Box } from '../design-system'
import { SearchTierBadge } from '../components/SearchTierBadge'
import { StatusChip } from '../components/StatusChip'
import { documentHref, recordHrefForType } from './recordLink'
import type { SearchResultHit } from '../types/search'

export function FeedReadingPane({ hit }: { hit: SearchResultHit | null }) {
  if (!hit) {
    return (
      <Container header={<Header variant="h3">Reading pane</Header>}>
        <Box variant="p">Select a result card to preview the record here.</Box>
      </Container>
    )
  }

  const href =
    hit.recordType === 'document'
      ? documentHref(hit.recordId)
      : recordHrefForType(hit.projectId, hit.recordType, hit.recordId)

  const typeLabel = hit.recordType.replace(/^\w/, (c) => c.toUpperCase())

  return (
    <Container
      header={
        <Header variant="h2" recordId={hit.recordId}>
          {typeLabel} · {hit.title}
        </Header>
      }
      footer={
        <a href={href} className="feed-route__detail-link">
          Open full record →
        </a>
      }
    >
      <div className="feed-reading-pane__meta">
        {hit.status ? <StatusChip status={hit.status} /> : null}
        <SearchTierBadge tier={hit.tier} />
        <span className="feed-reading-pane__project">{hit.projectId}</span>
      </div>
      <Box variant="p">{hit.title}</Box>
    </Container>
  )
}
