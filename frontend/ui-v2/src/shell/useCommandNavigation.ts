import { useNavigate } from '@tanstack/react-router'
import { useQuery } from '@tanstack/react-query'
import { projectRegistryQueryOptions, inferRecordNavigation } from '../api/projectRegistry'
import { useUiStore } from '../store/uiStore'
import { DOCUMENT_ROUTE_PATH, trackerRoutePath } from '../routes/recordLink'

/**
 * Shared record-id-to-route resolution for the search box, used by both
 * CommandPalette's full-screen overlay (mobile) and the anchored dropdown it
 * renders under the top-nav search input (desktop) -- kept in one place so
 * the two render modes can't drift on what counts as a navigable match.
 */
export function useCommandNavigation(query: string) {
  const navigate = useNavigate()
  const selectRecord = useUiStore((s) => s.selectRecord)
  const closeCommandPalette = useUiStore((s) => s.closeCommandPalette)

  const { data: projects = [] } = useQuery(projectRegistryQueryOptions)

  const nav = inferRecordNavigation(query, projects)
  const canGo = nav !== null && (nav.type === 'document' || nav.projectId !== null)

  function submit() {
    if (!nav || !canGo) return
    selectRecord(nav.id)
    closeCommandPalette()
    if (nav.type === 'document') {
      navigate({ to: DOCUMENT_ROUTE_PATH, params: { id: nav.id } })
      return
    }
    navigate({
      to: trackerRoutePath(nav.type),
      params: { project: nav.projectId as string, id: nav.id },
    })
  }

  return { nav, canGo, submit }
}
