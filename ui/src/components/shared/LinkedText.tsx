import { Link } from 'react-router-dom'

const ID_SPLIT = /\b([A-Z]+-(?:TSK|ISS|FTR)-\d{3,}|DOC-[A-F0-9]{12})\b/
const ID_TEST = /^(?:[A-Z]+-(?:TSK|ISS|FTR)-\d{3,}|DOC-[A-F0-9]{12})$/

function routeForId(id: string): string {
  if (id.startsWith('DOC-')) return `/documents/${id}`
  if (id.includes('-TSK-')) return `/tasks/${id}`
  if (id.includes('-ISS-')) return `/issues/${id}`
  if (id.includes('-FTR-')) return `/features/${id}`
  return '#'
}

export function LinkedText({ text, className }: { text: string; className?: string }) {
  if (!text) return null

  const parts = text.split(ID_SPLIT)

  return (
    <span className={className}>
      {parts.map((part, i) =>
        ID_TEST.test(part) ? (
          <Link
            key={i}
            to={routeForId(part)}
            className="text-blue-400 hover:text-blue-300 font-mono text-sm underline underline-offset-2"
          >
            {part}
          </Link>
        ) : (
          <span key={i}>{part}</span>
        ),
      )}
    </span>
  )
}
