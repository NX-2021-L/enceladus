import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { Cards } from '../design-system'
import { fetchGovernanceDocs, governanceDocKeys } from '../api/documents'
import { documentHref } from './recordLink'
import { useDocumentTitle } from '../hooks/useDocumentTitle'
import type { Document } from '../types/records'
import './governance.css'

/** The governed tracker is single-project today (ENC-TSK-M37): the project
 *  picker this route used to carry was pure redundancy -- a select with one
 *  real choice is not a control, it's decoration. Governance docs are
 *  fetched for the one governed project directly. */
const GOVERNANCE_PROJECT_ID = 'enceladus'

/**
 * ENC-TSK-K26 / ENC-ISS-121 — Live governance docs from the docstore API.
 * No stale mirror: every row is fetched via GET /api/v1/documents/search at
 * read time (governance-file + project-reference keywords).
 */
export function GovernanceRoute() {
  useDocumentTitle('Governance')

  const normalized = GOVERNANCE_PROJECT_ID
  const { data, isPending, isError, error } = useQuery({
    queryKey: governanceDocKeys.primaryReference(normalized),
    queryFn: () => fetchGovernanceDocs(normalized),
    enabled: normalized.length > 0,
    staleTime: 60_000,
  })

  const docs = data ?? []

  const cardDefinition = {
    header: (doc: Document) => (
      <Link to={documentHref(doc.document_id)} className="governance-route__card-link">
        {doc.title || doc.document_id}
      </Link>
    ),
    sections: [
      {
        id: 'documentId',
        header: 'Document',
        content: (doc: Document) => (
          <span className="governance-route__card-id">{doc.document_id}</span>
        ),
      },
      {
        id: 'file',
        header: 'File',
        content: (doc: Document) => (
          <span className="governance-route__card-file">{doc.file_name || '—'}</span>
        ),
      },
      {
        id: 'updated',
        header: 'Updated',
        content: (doc: Document) => doc.updated_at ?? '—',
      },
    ],
  }

  return (
    <div className="governance-route">
      <header className="governance-route__header">
        <p className="governance-route__eyebrow">GOVERNANCE · LIVE</p>
        <h1 className="governance-route__title">Governance documents</h1>
        <p className="governance-route__subtitle">
          agents.md, lifecycle-primer, dictionary, and project reference files, fetched live on
          each load.
        </p>
      </header>

      <div className="governance-route__toolbar">
        <p className="governance-route__meta">
          {isPending ? 'Loading…' : `${docs.length} document${docs.length === 1 ? '' : 's'}`}
        </p>
      </div>

      {isError ? (
        <p className="governance-route__meta governance-route__meta-error">
          {error instanceof Error ? error.message : 'Failed to load governance docs'}
        </p>
      ) : null}

      {!isPending && !isError && docs.length === 0 ? (
        <p className="governance-route__empty">No governance documents found for {normalized}.</p>
      ) : null}

      {!isPending && docs.length > 0 ? (
        <Cards items={docs} cardDefinition={cardDefinition} trackBy="document_id" />
      ) : null}
    </div>
  )
}
