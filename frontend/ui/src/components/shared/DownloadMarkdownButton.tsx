import { useCallback, useState } from 'react'
import type { Document } from '../../types/feeds'
import { documentMarkdownFileName, documentToMarkdown } from '../../lib/documentMarkdown'

const DownloadIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
    <polyline points="7 10 12 15 17 10" />
    <line x1="12" y1="15" x2="12" y2="3" />
  </svg>
)

const CheckIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="20 6 9 17 4 12" />
  </svg>
)

interface DownloadMarkdownButtonProps {
  document: Document
  className?: string
  size?: 'sm' | 'md'
}

/**
 * ENC-FTR-051 — mounts alongside the ENC-FTR-038 CopyButton in the document
 * detail page's control cluster. Mirrors its interaction contract exactly:
 * same tooltip (`title`), same aria-label toggle pattern, same inline
 * "success" affordance (no external toast system exists in this codebase —
 * CopyButton's own local `copied` state IS the success notification
 * pattern, so this component follows suit with a `downloaded` state).
 */
export function DownloadMarkdownButton({ document: doc, className = '', size = 'sm' }: DownloadMarkdownButtonProps) {
  const [downloaded, setDownloaded] = useState(false)

  const handleDownload = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault()
      e.stopPropagation()

      const markdown = documentToMarkdown(doc)
      const blob = new Blob([markdown], { type: 'text/markdown;charset=utf-8' })
      const url = URL.createObjectURL(blob)
      const anchor = window.document.createElement('a')
      anchor.href = url
      anchor.download = documentMarkdownFileName(doc)
      window.document.body.appendChild(anchor)
      anchor.click()
      window.document.body.removeChild(anchor)
      URL.revokeObjectURL(url)

      setDownloaded(true)
      setTimeout(() => setDownloaded(false), 2000)
    },
    [doc],
  )

  const padding = size === 'sm' ? 'p-1' : 'p-1.5'

  return (
    <button
      onClick={handleDownload}
      className={`${padding} rounded transition-colors ${
        downloaded
          ? 'text-emerald-400'
          : 'text-slate-500 hover:text-slate-300 active:text-slate-200'
      } ${className}`}
      title={downloaded ? 'Downloaded!' : 'Download markdown'}
      aria-label={downloaded ? 'Downloaded' : 'Download markdown'}
    >
      {downloaded ? <CheckIcon /> : <DownloadIcon />}
    </button>
  )
}
