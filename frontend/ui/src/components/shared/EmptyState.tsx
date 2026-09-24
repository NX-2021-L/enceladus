import { Link } from 'react-router-dom'

interface EmptyStateAction {
  label: string
  onClick?: () => void
  to?: string
}

export function EmptyState({ message, action }: { message?: string; action?: EmptyStateAction }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 px-4 text-center">
      <svg className="w-12 h-12 text-slate-600 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
      </svg>
      <p className="text-slate-500 text-sm">{message || 'No items to display'}</p>
      {action &&
        (action.to ? (
          <Link
            to={action.to}
            className="mt-3 text-xs font-medium text-teal-400 hover:text-teal-300 transition-colors"
          >
            {action.label}
          </Link>
        ) : (
          <button
            onClick={action.onClick}
            className="mt-3 text-xs font-medium text-teal-400 hover:text-teal-300 transition-colors"
          >
            {action.label}
          </button>
        ))}
    </div>
  )
}
