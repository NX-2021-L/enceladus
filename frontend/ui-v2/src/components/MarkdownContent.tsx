import { lazy, Suspense } from 'react'
import { MarkdownContentLegacy, resolveIdHref } from './MarkdownContentLegacy'
import { resolveMarkdownEngine } from '../utils/markdownEngine'
import type { MarkdownContentProps } from './markdownContentTypes'

export { resolveIdHref }
export type { MarkdownContentProps }

// The kit (unified/remark stack) loads as its own chunk; the legacy render is the Suspense
// fallback, so the first paint is byte-identical and nothing shifts when the chunk lands.
const KitMarkdownContent = lazy(() => import('./KitMarkdownContent'))

/**
 * MarkdownContent -- the one shared renderer for record descriptions, evidence, worklog entries
 * and document bodies. DVP-TSK-935: renders through @io-kit/md (lean) by default with the
 * host's own components and CSS so the DOM matches the legacy parser; `?md=legacy` (or the
 * ev2.md.engine preference) selects the legacy parser for one more release.
 */
export function MarkdownContent(props: MarkdownContentProps) {
  const source = props.text ?? props.content
  if (!source || !source.trim()) return null
  if (resolveMarkdownEngine() === 'legacy') return <MarkdownContentLegacy {...props} />
  return (
    <Suspense fallback={<MarkdownContentLegacy {...props} />}>
      <KitMarkdownContent {...props} />
    </Suspense>
  )
}
