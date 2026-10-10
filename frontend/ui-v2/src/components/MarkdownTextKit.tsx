import type { AnchorHTMLAttributes } from 'react'
import { useRouter } from '@tanstack/react-router'
import { KitMarkdown } from '@io-kit/md/lean/react'
import { code, idLinks, type IdResolver } from '@io-kit/md/lean'
import '@io-kit/md/docstore.css'
import { documentHref, recordHref } from '../routes/recordLink'

/** Internal (host-route) links navigate in-app; everything else keeps the browser default. */
export function HostLink({ href, children, ...rest }: AnchorHTMLAttributes<HTMLAnchorElement>) {
  const router = useRouter()
  const internal = !!href && href.startsWith('/') && !href.startsWith('//')
  return (
    <a
      href={href}
      {...rest}
      onClick={
        internal
          ? (e) => {
              if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
              e.preventDefault()
              router.history.push(href)
            }
          : rest.onClick
      }
    >
      {children}
    </a>
  )
}

const TRACKER_PREFIX_TO_TYPE = {
  TSK: 'task',
  ISS: 'issue',
  FTR: 'feature',
  PLN: 'plan',
  LSN: 'lesson',
} as const

/** Resolves a governed record-ID token to its detail route, or null (rendered as plain monospace, never a dead link). */
export function resolveIdHref(token: string, projectId: string | undefined): string | null {
  if (token.startsWith('DOC-')) return documentHref(token)
  const match = /^ENC-(TSK|ISS|FTR|PLN|LSN)-/.exec(token)
  if (match && projectId) return recordHref(projectId, TRACKER_PREFIX_TO_TYPE[match[1] as keyof typeof TRACKER_PREFIX_TO_TYPE], token)
  return null
}

/** The kit `core` profile (plain code fences) plus project-scoped id links. */
export default function MarkdownTextKit({ text, projectId, className }: { text: string; projectId?: string; className?: string }) {
  const resolver: IdResolver = (id) => {
    const href = resolveIdHref(id, projectId)
    return href ? { href, title: id } : null
  }
  return <KitMarkdown source={text} plugins={[code(), idLinks(resolver)]} components={{ a: HostLink } as never} className={className} />
}
