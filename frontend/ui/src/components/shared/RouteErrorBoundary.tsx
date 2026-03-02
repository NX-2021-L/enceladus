import { useRouteError } from 'react-router-dom'

export function RouteErrorBoundary() {
  useRouteError()
  return (
    <div className="p-6 text-center space-y-2">
      <p className="text-sm font-medium text-slate-300">Something went wrong loading this page.</p>
      <p className="text-xs text-slate-500">Try refreshing or navigating away and back.</p>
    </div>
  )
}
