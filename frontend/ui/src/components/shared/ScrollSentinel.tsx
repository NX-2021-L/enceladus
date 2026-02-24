interface ScrollSentinelProps {
  sentinelRef: (node: HTMLElement | null) => void
  hasMore: boolean
}

export function ScrollSentinel({ sentinelRef, hasMore }: ScrollSentinelProps) {
  return (
    <div ref={sentinelRef} className="flex justify-center py-4">
      {hasMore && (
        <div className="flex items-center gap-2 text-xs text-slate-500">
          <div className="w-4 h-4 border-2 border-slate-600 border-t-blue-400 rounded-full animate-spin" />
          Loading more...
        </div>
      )}
    </div>
  )
}
