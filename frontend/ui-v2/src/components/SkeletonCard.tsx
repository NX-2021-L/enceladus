/**
 * Suspense fallback. Each detail route wraps its component in a route-level
 * <Suspense fallback={<SkeletonCard />}> (AC-14). Void canvas, teal-alpha
 * border, 8px radius, orbital-eased shimmer — no spring physics (Law 4).
 * ENC-TSK-S63-0B (spec 6.10): shimmer over surface-raised and tint-teal-12; it stops
 * under prefers-reduced-motion.
 */
export function SkeletonCard({ label = 'Loading record' }: { label?: string }) {
  return (
    <div
      role="status"
      aria-busy="true"
      aria-label={label}
      style={{
        background: 'var(--surface)',
        border: '1px solid var(--border)',
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
      className="enc-skeleton-line"
      style={{
        width,
        height,
        borderRadius: 'var(--radius-sm)',
        background:
          'linear-gradient(90deg, var(--surface-raised) 0%, var(--tint-teal-12) 50%, var(--surface-raised) 100%)',
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
@media (prefers-reduced-motion: reduce) {
  .enc-skeleton-line { animation: none !important; }
}
`
