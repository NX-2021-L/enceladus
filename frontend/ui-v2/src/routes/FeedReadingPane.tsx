import { Suspense, type ComponentType } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Container, Header, Box } from '../design-system'
import { SkeletonCard } from '../components/SkeletonCard'
import { recordQueryOptions } from '../api/queryOptions'
import { getPrimitive } from '../primitives/registry'
import type { SearchResultHit } from '../types/search'

/**
 * FeedReadingPane -- the wide-viewport master-detail hub (FTR-128 AC-18,
 * ENC-TSK-M35). Selecting a feed row loads the record's real data and
 * renders it through the SAME `Primitive` (RecordDetailHub: Overview ·
 * Neighbors · Worklog · Evidence tabs) used by the full-page record routes
 * (routes/recordRoute.tsx) -- this is a merged in-place view, not a
 * duplicate summary. No separate renderer is forked here.
 *
 * Description/body text renders through each Primitive's existing <Prose>
 * component (plaintext today). Lane L1 is landing a shared MarkdownContent
 * component for description rendering elsewhere in the primitive stack --
 * because this pane reuses the primitives verbatim rather than re-rendering
 * the description itself, it inherits that upgrade automatically on the next
 * rebase with no changes needed here.
 */
export function FeedReadingPane({ hit }: { hit: SearchResultHit | null }) {
  if (!hit) {
    return (
      <Container header={<Header variant="h3">Reading pane</Header>}>
        <Box variant="p">Select a result card to preview the record here.</Box>
      </Container>
    )
  }

  return <FeedReadingPaneRecord key={`${hit.recordType}:${hit.recordId}`} hit={hit} />
}

function FeedReadingPaneRecord({ hit }: { hit: SearchResultHit }) {
  const projectId = hit.projectId || 'enceladus'
  const options =
    hit.recordType === 'document'
      ? recordQueryOptions.document(hit.recordId, projectId)
      : recordQueryOptions[hit.recordType](projectId, hit.recordId)

  const { data, isLoading, isError } = useQuery(options)

  if (isLoading) {
    return <SkeletonCard label={`Loading ${hit.recordType}`} />
  }

  if (isError || !data) {
    return (
      <Container header={<Header variant="h3">Reading pane</Header>}>
        <Box variant="p">Couldn't load {hit.recordId} — try selecting it again.</Box>
      </Container>
    )
  }

  // Runtime dispatch across the six record-shape primitives: `hit.recordType`
  // is a union at this point (not narrowed to a single literal K), so this
  // boundary needs one cast -- the same pattern routes/recordRoute.tsx already
  // uses (`route.useParams() as {...}`) for the equivalent dynamic-type seam.
  const Primitive = getPrimitive(hit.recordType) as ComponentType<{ record: unknown }>

  return (
    <Suspense fallback={<SkeletonCard label={`Loading ${hit.recordType}`} />}>
      <Primitive record={data} />
    </Suspense>
  )
}
