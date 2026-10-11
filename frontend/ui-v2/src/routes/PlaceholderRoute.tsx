import { PageHeader } from '../components/PageHeader'
import { useDocumentTitle } from '../hooks/useDocumentTitle'

/** Scaffold page for cockpit nav targets not yet built out (ENC-ISS-513 /
 * FND-02: no build-wave codenames or route plumbing in operator copy). */
export function PlaceholderRoute({ title }: { title: string }) {
  useDocumentTitle(title)

  return (
    <div className="ev2-placeholder ev2-page">
      <PageHeader title={title} description="This page isn't available yet." />
    </div>
  )
}
