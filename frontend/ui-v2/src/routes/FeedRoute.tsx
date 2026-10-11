import { lazy, Suspense } from 'react'

// DVP-TSK-995: /feed is the kit CollectionSearch page (feed/FeedSearchPage). The page and its Cloudscape chunk load
// lazily, so the initial route budget is unchanged. The ?feed=legacy rollback (src/sync engine) is retired.
const FeedSearchPage = lazy(() => import('../feed/FeedSearchPage'))

export function FeedRoute() {
  return (
    <Suspense fallback={null}>
      <FeedSearchPage />
    </Suspense>
  )
}
