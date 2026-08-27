import type { ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { projectRegistryQueryOptions } from '../api/projectRegistry'
import { resolveRecordTarget } from '../routes/recordLink'

/**
 * ENC-TSK-P59 — the shared record link (UAT-W2).
 *
 * Renders a real anchor for any governed record id via the UAT-W1 resolver
 * (ENC-TSK-P58): tracker types route per owning project, DOC-* to the
 * document route, ENC-SES-* to the session page, ENC-AGT-* to the agent
 * page. When the id cannot be resolved (unknown prefix, still-loading
 * project registry, non-record text) it degrades to a plain span rather
 * than a dead or guessed link — link-styled-but-inert is the defect class
 * this component exists to end (ENC-ISS-717/723/724/725).
 */
export function RecordLink({
  id,
  recordType,
  className,
  children,
}: {
  id: string
  recordType?: string
  className?: string
  children?: ReactNode
}) {
  const { data: projects = [] } = useQuery(projectRegistryQueryOptions)
  const target = resolveRecordTarget(id, projects, recordType)
  if (!target) return <span className={className}>{children ?? id}</span>
  return (
    <Link to={target.to} params={target.params} className={className}>
      {children ?? id}
    </Link>
  )
}
