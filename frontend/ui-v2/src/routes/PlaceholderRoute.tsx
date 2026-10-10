import { useDocumentTitle } from '../hooks/useDocumentTitle'

/** Scaffold page for cockpit nav targets not yet built out (ENC-ISS-513 /
 * FND-02: no build-wave codenames or route plumbing in operator copy). */
export function PlaceholderRoute({ title }: { title: string }) {
  useDocumentTitle(title)

  return (
    <div className="ev2-placeholder">
      <p className="ev2-placeholder__eyebrow">COMING SOON</p>
      <h1 className="ev2-placeholder__title">{title}</h1>
      <p className="ev2-placeholder__body">This page isn't available yet.</p>
    </div>
  )
}
