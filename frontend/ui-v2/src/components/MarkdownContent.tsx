/**
 * MarkdownContent — Content-tab renderer for full document bodies
 * (ENC-TSK-M34, Docs.dc.html §"CONTENT · rendered markdown").
 *
 * TODO(ENC-TSK-M34 / concurrent lane L1): a shared, fully-interpreted
 * Markdown renderer is being built on `agent/enc-tsk-m35-m36-feed` for the
 * Feed reading pane. Per dispatch instruction this component is the
 * *sanctioned interim* — safe plaintext (no HTML injection, whitespace
 * preserved) behind this TODO — and must be replaced by an import of the
 * shared component once that lane merges. Do NOT hand-roll a second
 * Markdown-to-HTML parser here; if the shared component isn't available yet,
 * keep this plaintext fallback.
 */
export function MarkdownContent({ content }: { content: string | undefined }) {
  if (!content) {
    return (
      <p style={{ fontFamily: 'var(--font-body)', fontSize: 'var(--text-sm)', color: 'var(--fg-muted)' }}>
        No content available.
      </p>
    )
  }

  return (
    <pre
      className="ev2-md-content"
      style={{
        margin: 0,
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-word',
        fontFamily: 'var(--font-body)',
        fontSize: 'var(--text-sm)',
        lineHeight: 'var(--lh-relaxed)',
        color: 'var(--fg)',
      }}
    >
      {content}
    </pre>
  )
}
