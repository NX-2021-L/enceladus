/**
 * ENC-TSK-S98-0C (ENC-PLN-108 W3.3): the /plans route — the change that makes the Plans page visible.
 *
 * DOC-5E1E205FA664 section 5.9. The route is lazy and declared like /projects; `?project=` is validated like /docs
 * and is the single source of truth for the filter, so a filtered view is a shareable URL and the back button works.
 *
 * The page itself fetches nothing: `usePlansLens` reads the already-seeded corpus for structure and makes exactly
 * one plan-scoped request for the time scale (ENC-TSK-T05). No timer and no polling are added here — freshness
 * belongs to the corpus heal loop, which already runs on every route (section 5.8).
 */

import { useNavigate, useSearch } from '@tanstack/react-router'
import { PlansPage } from '../plans/PlansPage'
import { usePlansLens } from '../plans/usePlansLens'

export function PlansRoute() {
  const { project } = useSearch({ from: '/plans' }) as { project: string }
  const navigate = useNavigate()
  const lens = usePlansLens()

  return (
    <PlansPage
      corpus={lens.rows}
      now={Date.now()}
      asOf={lens.asOf}
      stale={lens.stale}
      loading={lens.loading}
      error={lens.error}
      onRefresh={lens.refresh}
      project={project ?? ''}
      onProjectChange={(next) => {
        // Replace rather than push: flicking through the filter should not bury the previous page in history.
        void navigate({ to: '/plans', search: next ? { project: next } : {}, replace: true })
      }}
    />
  )
}
