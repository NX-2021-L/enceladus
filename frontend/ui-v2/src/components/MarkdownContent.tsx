import { lazy, Suspense } from 'react'
import { resolveIdHref } from './markdownIds'
import type { MarkdownContentProps } from './markdownContentTypes'

export { resolveIdHref }
export type { MarkdownContentProps }

// The kit (unified/remark stack) is its own chunk to keep the initial route inside the bundle budget.
// Its fetch starts as soon as this module loads, so it is normally ready before any record or document
// data arrives and the fallback below is rarely painted. A failed fetch is retried once on first render.
const kitChunk = import('./KitMarkdownContent')
kitChunk.catch(() => undefined)
const KitMarkdownContent = lazy(() => kitChunk.catch(() => import('./KitMarkdownContent')))

/**
 * MarkdownContent -- the one shared renderer for record descriptions, evidence, worklog entries
 * and document bodies. DVP-TSK-935: renders through @io-kit/md (lean) with the host's own
 * components and CSS, so the DOM matches the retired legacy parser (asserted against the frozen
 * oracle in __parity__/ by KitMarkdownContent.parity.test.tsx). The `?md=legacy` switch shipped
 * for one release and is gone.
 */
export function MarkdownContent(props: MarkdownContentProps) {
  const source = props.text ?? props.content
  if (!source || !source.trim()) return null
  return (
    <Suspense
      fallback={
        <div className={`ev2-md${props.className ? ` ${props.className}` : ''}`} style={{ whiteSpace: 'pre-wrap' }}>
          {source}
        </div>
      }
    >
      <KitMarkdownContent {...props} />
    </Suspense>
  )
}
