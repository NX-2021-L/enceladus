import { freshnessBadge } from '../../lib/formatters'

export function FreshnessBadge({ generatedAt }: { generatedAt: string | null }) {
  if (!generatedAt) return null
  const { label, stale } = freshnessBadge(generatedAt)
  return (
    <span
      className={`inline-flex items-center gap-1 text-xs ${
        stale ? 'text-amber-400' : 'text-emerald-400'
      }`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${stale ? 'bg-amber-400' : 'bg-emerald-400'}`} />
      {label}
    </span>
  )
}
