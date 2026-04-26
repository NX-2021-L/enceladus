/**
 * RecordFallbackError — transient-failure state for the direct-API fallback
 * path (ENC-FTR-073 Phase 2c / ENC-TSK-D96).
 *
 * Displayed for non-404 failures (network timeout, 5xx, auth error once the
 * session has already rehydrated). Provides a retry affordance when the
 * caller wires `onRetry` to the hook's `refetch` callback.
 *
 * Pure presentational — no hooks, no data coupling. Accessibility:
 *   - role="alert" + aria-live="assertive" so the transition is announced by
 *     screen readers.
 *   - Retry button is only rendered when `onRetry` is provided.
 */

interface Props {
  onRetry?: () => void
  message?: string
}

export function RecordFallbackError({ onRetry, message }: Props) {
  const detail = message && message.length > 0
    ? message
    : 'We could not load this record. Check your connection and try again.'
  return (
    <div
      role="alert"
      aria-live="assertive"
      className="flex flex-col items-center justify-center py-16 px-4 text-center"
    >
      <svg
        className="w-12 h-12 text-red-400 mb-3"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
        strokeWidth={1.5}
        aria-hidden="true"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4.5c-.77-.833-2.694-.833-3.464 0L3.34 16.5c-.77.833.192 2.5 1.732 2.5z"
        />
      </svg>
      <h2 className="text-slate-200 text-base font-semibold">Failed to load record</h2>
      <p className="text-slate-400 text-sm mt-1 max-w-sm">{detail}</p>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="mt-4 inline-flex items-center rounded-md bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:ring-offset-2 focus:ring-offset-slate-900"
        >
          Retry
        </button>
      )}
    </div>
  )
}
