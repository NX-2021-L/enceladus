/**
 * RecordFallbackLoading — accessible loading indicator for the fallback-fetch
 * path (ENC-FTR-073 Phase 2c / ENC-TSK-D96).
 *
 * Pure presentational. Matches the existing <LoadingState /> visual grammar
 * (slate spinner, 16 py) so detail pages render identically regardless of
 * whether the record came from the feed or the direct API.
 *
 * Accessibility:
 *   - role="status" + aria-live="polite" so screen readers announce the
 *     transition into loading state.
 *   - aria-busy="true" on the container while the fetch is in flight.
 *   - Visible label is an SR-only text by default but can be overridden via
 *     the `label` prop.
 */

interface Props {
  label?: string
}

export function RecordFallbackLoading({ label = 'Loading record...' }: Props) {
  return (
    <div
      role="status"
      aria-live="polite"
      aria-busy="true"
      className="flex items-center justify-center py-16"
    >
      <div
        className="w-8 h-8 border-2 border-slate-600 border-t-blue-400 rounded-full animate-spin"
        aria-hidden="true"
      />
      <span className="sr-only">{label}</span>
    </div>
  )
}
