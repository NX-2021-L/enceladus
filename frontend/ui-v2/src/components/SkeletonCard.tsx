/**
 * Suspense fallback. Each detail route wraps its component in a route-level
 * <Suspense fallback={<SkeletonCard />}> (AC-14). Void canvas, teal-alpha
 * border, 8px radius, orbital-eased shimmer — no spring physics (Law 4).
 */
export function SkeletonCard({ label = 'Loading record' }: { label?: string }) {
  return (
    <div
      role="status"
      aria-busy="true"
      aria-label={label}
      style={{
        background: 'var(--bg-surface)',
        border: 'var(--border-subtle)',
        borderRadius: 'var(--radius-lg)',
        padding: 'var(--space-6)',
        boxShadow: 'var(--shadow-md)',
        display: 'flex',
        flexDirection: 'column',
        gap: 'var(--space-4)',
      }}
    >
      <SkeletonLine width="40%" height={12} />
      <SkeletonLine width="75%" height={28} />
      <SkeletonLine width="100%" height={12} />
      <SkeletonLine width="90%" height={12} />
      <SkeletonLine width="60%" height={12} />
      <style>{shimmerKeyframes}</style>
    </div>
  )
}

function SkeletonLine({ width, height }: { width: string; height: number }) {
  return (
    <div
      style={{
        width,
        height,
        borderRadius: 'var(--radius-sm)',
        background:
          'linear-gradient(90deg, var(--enc-surface-alt) 0%, var(--enc-slate) 50%, var(--enc-surface-alt) 100%)',
        backgroundSize: '200% 100%',
        animation: 'enc-shimmer 1.4s var(--ease-orbit) infinite',
      }}
    />
  )
}

const shimmerKeyframes = `
@keyframes enc-shimmer {
  0% { background-position: 200% 0; }
  100% { background-position: -200% 0; }
}
`
