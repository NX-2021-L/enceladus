import { lazy, Suspense } from 'react'

// DVP-TSK-995: the Cloudscape-backed search page is a lazy chunk of the (already lazy) route.
const DocsSearchPage = lazy(() => import('./DocsSearchPage'))

export function DocsRoute() {
  return (
    <Suspense fallback={null}>
      <DocsSearchPage />
    </Suspense>
  )
}
