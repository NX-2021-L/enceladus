import { lazy, Suspense } from 'react'

// DVP-TSK-924: governed text (descriptions, worklogs, evidence) renders through @io-kit/md's core profile.
// Lazy so the unified/remark stack stays out of the initial route; the fallback is the raw text.
const MarkdownTextKit = lazy(() => import('./MarkdownTextKit'))

export function MarkdownText({ text, projectId, className }: { text: string | null | undefined; projectId?: string; className?: string }) {
  if (!text || !text.trim()) return null
  return (
    <Suspense fallback={<p className={className} style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{text}</p>}>
      <MarkdownTextKit text={text} projectId={projectId} className={className} />
    </Suspense>
  )
}
