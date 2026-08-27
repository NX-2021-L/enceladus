import { useNavigate } from '@tanstack/react-router'
import { useQuery } from '@tanstack/react-query'
import { projectRegistryQueryOptions, inferRecordNavigation } from '../api/projectRegistry'
import { useUiStore } from '../store/uiStore'
import { resolveRecordTarget } from '../routes/recordLink'

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
    // ENC-TSK-P58: same resolver as the plan-graph tap handler — one
    // id→route seam for every navigation surface.
    const target = resolveRecordTarget(nav.id, projects, nav.type)
    if (!target) return
    selectRecord(nav.id)
    closeCommandPalette()
    void navigate(target)
  }

  return { nav, canGo, submit }
}
