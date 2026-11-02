import type { ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { projectRegistryQueryOptions } from '../api/projectRegistry'
import { resolveRecordTarget } from '../routes/recordLink'
import { CopyIdButton } from './CopyIdButton'

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
 *
 * ENC-TSK-R80-0H / ENC-FTR-151 AC-5: `copyable` appends a copy button to the
 * right of the ID that copies the bare id (not the link text) without
 * navigating. The button is a sibling of the anchor, never nested in it.
 */
export function RecordLink({
  id,
  recordType,
  className,
  children,
  copyable = false,
}: {
  id: string
  recordType?: string
  className?: string
  children?: ReactNode
  /** Render a copy-ID button immediately right of the link. */
  copyable?: boolean
}) {
  const { data: projects = [] } = useQuery(projectRegistryQueryOptions)
  const target = resolveRecordTarget(id, projects, recordType)
  const link = target ? (
    <Link to={target.to} params={target.params} className={className}>
      {children ?? id}
    </Link>
  ) : (
    <span className={className}>{children ?? id}</span>
  )
  if (!copyable) return link
  return (
    <span className="enc-record-link-copyable">
      {link}
      <CopyIdButton id={id} />
    </span>
  )
}
