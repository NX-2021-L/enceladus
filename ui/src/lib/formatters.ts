export function formatDate(iso: string | null): string {
  if (!iso) return '—'
  try {
    const d = new Date(iso)
    if (isNaN(d.getTime())) return '—'
    const pad = (n: number) => String(n).padStart(2, '0')
    const yyyy = d.getFullYear()
    const mm = pad(d.getMonth() + 1)
    const dd = pad(d.getDate())
    const hh = pad(d.getHours())
    const min = pad(d.getMinutes())
    const ss = pad(d.getSeconds())
    const tz =
      d
        .toLocaleTimeString('en-US', { timeZoneName: 'short' })
        .split(' ')
        .pop() ?? ''
    return `${yyyy}-${mm}-${dd} ${hh}:${min}:${ss} ${tz}`
  } catch {
    return '—'
  }
}

export function timeAgo(iso: string | null): string {
  if (!iso) return ''
  try {
    const d = new Date(iso)
    if (isNaN(d.getTime())) return ''
    const now = Date.now()
    const diff = now - d.getTime()
    const mins = Math.floor(diff / 60000)
    if (mins < 1) return 'just now'
    if (mins < 60) return `${mins}m ago`
    const hours = Math.floor(mins / 60)
    if (hours < 24) return `${hours}h ago`
    const days = Math.floor(hours / 24)
    if (days < 30) return `${days}d ago`
    const months = Math.floor(days / 30)
    return `${months}mo ago`
  } catch {
    return ''
  }
}

export function freshnessBadge(generatedAt: string): { label: string; stale: boolean } {
  try {
    const d = new Date(generatedAt)
    const mins = Math.floor((Date.now() - d.getTime()) / 60000)
    if (mins < 5) return { label: 'Live', stale: false }
    if (mins < 60) return { label: `${mins}m old`, stale: false }
    const hours = Math.floor(mins / 60)
    if (hours < 24) return { label: `${hours}h old`, stale: hours > 1 }
    return { label: `${Math.floor(hours / 24)}d old`, stale: true }
  } catch {
    return { label: 'Unknown', stale: true }
  }
}
