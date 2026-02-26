import { timeAgo } from '../../lib/formatters'

interface CheckoutStateBadgeProps {
  activeSession?: boolean
  checkoutState?: 'checked_out' | 'checked_in' | null
  checkedOutBy?: string | null
  checkedOutAt?: string | null
  checkedInBy?: string | null
  checkedInAt?: string | null
}

export function CheckoutStateBadge({
  activeSession,
  checkoutState,
  checkedOutBy,
  checkedOutAt,
  checkedInBy,
  checkedInAt,
}: CheckoutStateBadgeProps) {
  if (activeSession || checkoutState === 'checked_out') {
    const who = checkedOutBy ? ` by ${checkedOutBy}` : ''
    const when = checkedOutAt ? ` (${timeAgo(checkedOutAt)})` : ''
    return (
      <span
        className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium bg-amber-500/20 text-amber-300"
        title={`Checked out${who}${when}`}
      >
        Checked Out
      </span>
    )
  }

  if (checkoutState === 'checked_in') {
    const who = checkedInBy ? ` by ${checkedInBy}` : ''
    const when = checkedInAt ? ` (${timeAgo(checkedInAt)})` : ''
    return (
      <span
        className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium bg-sky-500/20 text-sky-300"
        title={`Checked in${who}${when}`}
      >
        Checked In
      </span>
    )
  }

  return null
}
