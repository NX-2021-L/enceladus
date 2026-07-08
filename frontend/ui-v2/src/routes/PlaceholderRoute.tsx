import { useRouterState } from '@tanstack/react-router'
import { useDocumentTitle } from '../hooks/useDocumentTitle'

/** Scaffold page for cockpit nav targets filled in by L30–L34. */
export function PlaceholderRoute({ title }: { title: string }) {
  const pathname = useRouterState({ select: (s) => s.location.pathname })
  useDocumentTitle(title)

  return (
    <div className="ev2-placeholder">
      <p className="ev2-placeholder__eyebrow">Coming in catalog wave B</p>
      <h1 className="ev2-placeholder__title">{title}</h1>
      <p className="ev2-placeholder__body">
        Route <code className="ev2-placeholder__path">{pathname}</code> is wired in the
        design-system shell; page content lands in a follow-on task.
      </p>
    </div>
  )
}
