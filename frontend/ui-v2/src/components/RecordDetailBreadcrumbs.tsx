import { useNavigate } from '@tanstack/react-router'
import { BreadcrumbGroup } from '../design-system'
import { loadFeedReturnSearch } from '../search/feedSearchParams'

export function RecordDetailBreadcrumbs({ recordId }: { recordId: string }) {
  const navigate = useNavigate()

  return (
    <nav style={{ marginBottom: 'var(--space-5)' }}>
      <BreadcrumbGroup
        items={[
          { text: 'Feed', href: '/feed' },
          { text: recordId },
        ]}
        onFollow={(event) => {
          if (event.detail.item.text !== 'Feed') return
          navigate({ to: '/feed', search: loadFeedReturnSearch() })
        }}
      />
    </nav>
  )
}
