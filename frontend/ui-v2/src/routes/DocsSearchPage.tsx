import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearch } from '@tanstack/react-router'
import type { Query } from '@io-kit/search'
import { CollectionSearch } from '@io-kit/search-ui/cloudscape'
import { Alert } from '../design-system'
import { projectRegistryQueryOptions } from '../api/projectRegistry'
import { useDocumentTitle } from '../hooks/useDocumentTitle'
import { useEnceladusCorpus } from '../search/CorpusProvider'
import { hostSearchSource } from '../search/enceladusSearchSource'
import { DOCS_PROPERTIES } from '../search/propertyDefs'
import { rowToHit } from '../search/rowHit'
import { SORT_OPTIONS } from '../search/sortOptions'
import { renderFeedRow } from '../feed/FeedRowCard'
import '@io-kit/search-ui/theme.css'
import '@io-kit/search-ui/components.css'
import '@io-kit/search-ui/themes/enceladus.css'
import './docs.css'

const DATE_PRESETS = [
  { key: '7d', days: 7 },
  { key: '30d', days: 30 },
]

/**
 * DVP-TSK-995: /docs on the same kit CollectionSearch, over the document sequence space (record_type=document).
 * `?project=<id>` (project-card Docs link, ENC-TSK-P59) seeds a visible, removable project_id token.
 */
export default function DocsSearchPage() {
  useDocumentTitle('Docs')
  const { project, focus } = useSearch({ from: '/docs' }) as { project: string; focus?: 1 }
  const [query, setQuery] = useState<Query>(() => ({
    operation: 'and',
    tokens: project ? [{ propertyKey: 'project_id', operator: '=', value: project }] : [],
  }))
  const [sortId, setSortId] = useState('updated')
  const corpus = useEnceladusCorpus()
  const { data: projects = [] } = useQuery(projectRegistryQueryOptions)
  const docs = corpus.rows.filter((r) => r.type === 'document')

  return (
    <div className="docs-route">
      {corpus.staleNotice ? (
        <div className="docs-route__stale">
          <Alert type="warning" header="Documents may be out of date">
            {corpus.staleNotice}
          </Alert>
        </div>
      ) : null}
      <CollectionSearch
        title="Documents"
        things="documents"
        rows={docs}
        properties={DOCS_PROPERTIES}
        query={query}
        onQueryChange={setQuery}
        sortOptions={SORT_OPTIONS}
        sortId={sortId}
        onSortChange={setSortId}
        dateRange={{ propertyKey: 'updated_at', presets: DATE_PRESETS }}
        savedFilters={{ store: docSavedStore, surface: 'docs' }}
        hybrid={{
          source: hostSearchSource,
          filters: { project_id: projects[0]?.project_id ?? 'enceladus', record_type: 'document' },
          hardCapMs: 15_000,
        }}
        corpusPending={corpus.status === 'seeding' && docs.length === 0}
        error={corpus.status === 'error' ? corpus.error : null}
        placeholder="Search documents"
        pageSize={50}
        restoreKey="docs"
        autoFocus={focus === 1}
        renderRow={(row, ctx) =>
          renderFeedRow(rowToHit(row, ctx.hybrid), {
            projects,
            isWide: false,
            selectedHit: null,
            onSelect: () => {},
            onLeave: () => {},
            evidenceFor: () => undefined,
            pins: {},
            onPin: () => {},
          })
        }
      />
    </div>
  )
}

import { localSavedFilterStore as docSavedStore } from '../search/savedSearchMigration'
