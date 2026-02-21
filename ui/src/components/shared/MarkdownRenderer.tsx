import { Fragment, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import ReactMarkdown from 'react-markdown'
import type { Components, ExtraProps } from 'react-markdown'
import { CodeBlock } from './CodeBlock'

// Matches XXX-TSK-NNN, XXX-ISS-NNN, XXX-FTR-NNN (with optional child suffix), and DOC-XXXXXXXXXXXX
const ID_PATTERN = /\b([A-Z]{2,4}-(?:TSK|ISS|FTR)-\d{3}(?:-\d[A-Z])?|DOC-[A-F0-9]{12})\b/g

function idToPath(id: string): string {
  if (id.startsWith('DOC-')) return `/documents/${id}`
  const parts = id.split('-')
  const type = parts[1]
  const typeMap: Record<string, string> = { TSK: 'tasks', ISS: 'issues', FTR: 'features' }
  const route = typeMap[type]
  return route ? `/${route}/${id}` : ''
}

function linkifyText(text: string): React.ReactNode {
  const parts: React.ReactNode[] = []
  let lastIndex = 0
  let match: RegExpExecArray | null
  ID_PATTERN.lastIndex = 0
  while ((match = ID_PATTERN.exec(text)) !== null) {
    if (match.index > lastIndex) parts.push(text.slice(lastIndex, match.index))
    const id = match[1]
    const path = idToPath(id)
    if (path) {
      parts.push(
        <Link
          key={`${id}-${match.index}`}
          to={path}
          className="text-blue-400 underline underline-offset-2 font-mono text-[0.85em] hover:text-blue-300"
        >
          {id}
        </Link>,
      )
    } else {
      parts.push(id)
    }
    lastIndex = match.index + match[0].length
  }
  if (lastIndex < text.length) parts.push(text.slice(lastIndex))
  return parts.length === 1 && typeof parts[0] === 'string' ? parts[0] : (
    <>{parts.map((p, i) => <Fragment key={i}>{p}</Fragment>)}</>
  )
}

function processChildren(children: React.ReactNode): React.ReactNode {
  if (typeof children === 'string') return linkifyText(children)
  if (Array.isArray(children))
    return children.map((child, i) => (
      <Fragment key={i}>{typeof child === 'string' ? linkifyText(child) : child}</Fragment>
    ))
  return children
}

/**
 * Generate a slug from heading text, following GitHub anchor conventions:
 * lowercase, spaces→hyphens, strip punctuation, strip markup.
 */
function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/--+/g, '-')
    .replace(/^-+|-+$/g, '')
}

/** Extract plain text from React children (heading content may be nested elements). */
function extractText(children: React.ReactNode): string {
  if (typeof children === 'string') return children
  if (typeof children === 'number') return String(children)
  if (Array.isArray(children)) return children.map(extractText).join('')
  if (children && typeof children === 'object' && 'props' in children) {
    return extractText((children as { props: { children?: React.ReactNode } }).props.children)
  }
  return ''
}

const mdComponents: Components = {
  h1: ({ children, ...rest }: React.HTMLAttributes<HTMLHeadingElement> & ExtraProps) => {
    const id = slugify(extractText(children))
    return (
      <h1 id={id} className="text-xl font-bold text-slate-100 mt-6 mb-2 scroll-mt-16" {...rest}>
        {processChildren(children)}
      </h1>
    )
  },
  h2: ({ children, ...rest }: React.HTMLAttributes<HTMLHeadingElement> & ExtraProps) => {
    const id = slugify(extractText(children))
    return (
      <h2 id={id} className="text-lg font-semibold text-slate-200 mt-5 mb-2 border-b border-slate-700 pb-1 scroll-mt-16" {...rest}>
        {processChildren(children)}
      </h2>
    )
  },
  h3: ({ children, ...rest }: React.HTMLAttributes<HTMLHeadingElement> & ExtraProps) => {
    const id = slugify(extractText(children))
    return (
      <h3 id={id} className="text-base font-semibold text-slate-300 mt-4 mb-1 scroll-mt-16" {...rest}>
        {processChildren(children)}
      </h3>
    )
  },
  h4: ({ children, ...rest }: React.HTMLAttributes<HTMLHeadingElement> & ExtraProps) => {
    const id = slugify(extractText(children))
    return (
      <h4 id={id} className="text-sm font-semibold text-slate-400 mt-3 mb-1 scroll-mt-16" {...rest}>
        {processChildren(children)}
      </h4>
    )
  },
  h5: ({ children, ...rest }: React.HTMLAttributes<HTMLHeadingElement> & ExtraProps) => {
    const id = slugify(extractText(children))
    return (
      <h5 id={id} className="text-sm font-medium text-slate-400 mt-2 mb-1 scroll-mt-16" {...rest}>
        {processChildren(children)}
      </h5>
    )
  },
  h6: ({ children, ...rest }: React.HTMLAttributes<HTMLHeadingElement> & ExtraProps) => {
    const id = slugify(extractText(children))
    return (
      <h6 id={id} className="text-xs font-medium text-slate-500 mt-2 mb-1 scroll-mt-16" {...rest}>
        {processChildren(children)}
      </h6>
    )
  },
  p: ({ children, ...rest }: React.HTMLAttributes<HTMLParagraphElement> & ExtraProps) => (
    <p className="text-sm text-slate-300 mb-3 leading-relaxed" {...rest}>
      {processChildren(children)}
    </p>
  ),
  li: ({ children, ...rest }: React.LiHTMLAttributes<HTMLLIElement> & ExtraProps) => (
    <li className="text-sm text-slate-300 leading-relaxed" {...rest}>
      {processChildren(children)}
    </li>
  ),
  ul: ({ children }: React.HTMLAttributes<HTMLUListElement> & ExtraProps) => (
    <ul className="list-disc list-inside mb-3 space-y-0.5 text-slate-300">{children}</ul>
  ),
  ol: ({ children }: React.OlHTMLAttributes<HTMLOListElement> & ExtraProps) => (
    <ol className="list-decimal list-inside mb-3 space-y-0.5 text-slate-300">{children}</ol>
  ),
  code: ({ children, className }: React.HTMLAttributes<HTMLElement> & ExtraProps) => {
    // Fenced code blocks get language-xxx className from react-markdown
    const langMatch = typeof className === 'string' ? className.match(/language-(\w+)/) : null
    if (langMatch) {
      const code = String(children).replace(/\n$/, '')
      return <CodeBlock code={code} language={langMatch[1]} />
    }
    // Inline code
    return (
      <code className="bg-slate-800 rounded px-1.5 py-0.5 text-xs text-amber-300 font-mono">
        {children}
      </code>
    )
  },
  pre: ({ children }: React.HTMLAttributes<HTMLPreElement> & ExtraProps) => {
    // If children is already a CodeBlock (from our code component above), pass through
    // Otherwise wrap unfenced code blocks with basic highlighting
    if (
      children &&
      typeof children === 'object' &&
      'type' in children &&
      (children as { type: unknown }).type === CodeBlock
    ) {
      return <>{children}</>
    }
    // Unfenced code blocks (indented) — render with CodeBlock but no language
    const text = typeof children === 'string' ? children : ''
    if (text) return <CodeBlock code={text} showLabel={false} />
    return <>{children}</>
  },
  blockquote: ({ children }: React.BlockquoteHTMLAttributes<HTMLElement> & ExtraProps) => (
    <blockquote className="border-l-2 border-slate-600 pl-3 my-3 text-slate-400 italic text-sm">
      {children}
    </blockquote>
  ),
  table: ({ children }: React.TableHTMLAttributes<HTMLTableElement> & ExtraProps) => (
    <div className="overflow-x-auto mb-4">
      <table className="text-xs text-slate-300 border-collapse w-full">{children}</table>
    </div>
  ),
  th: ({ children }: React.ThHTMLAttributes<HTMLTableCellElement> & ExtraProps) => (
    <th className="border border-slate-700 bg-slate-800 px-2 py-1 text-left font-medium text-slate-200">
      {processChildren(children)}
    </th>
  ),
  td: ({ children }: React.TdHTMLAttributes<HTMLTableCellElement> & ExtraProps) => (
    <td className="border border-slate-700 px-2 py-1">{processChildren(children)}</td>
  ),
  hr: () => <hr className="border-slate-700 my-4" />,
  a: ({ href, children }: React.AnchorHTMLAttributes<HTMLAnchorElement> & ExtraProps) => {
    // Internal anchor links — scroll to element on the same page
    if (href && href.startsWith('#')) {
      return (
        <a
          href={href}
          onClick={(e) => {
            e.preventDefault()
            const target = document.getElementById(href.slice(1))
            if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' })
          }}
          className="text-blue-400 underline underline-offset-2 hover:text-blue-300"
        >
          {children}
        </a>
      )
    }
    // External links
    return (
      <a
        href={href}
        target="_blank"
        rel="noopener noreferrer"
        className="text-blue-400 underline underline-offset-2 hover:text-blue-300"
      >
        {children}
      </a>
    )
  },
  strong: ({ children }: React.HTMLAttributes<HTMLElement> & ExtraProps) => (
    <strong className="font-semibold text-slate-200">{processChildren(children)}</strong>
  ),
  em: ({ children }: React.HTMLAttributes<HTMLElement> & ExtraProps) => (
    <em className="italic text-slate-300">{processChildren(children)}</em>
  ),
}

interface MarkdownRendererProps {
  content: string
  className?: string
}

export function MarkdownRenderer({ content, className }: MarkdownRendererProps) {
  const { hash } = useLocation()

  // On mount or hash change, scroll to the anchor if present
  useEffect(() => {
    if (hash) {
      // Small delay to let react-markdown render headings
      const timer = setTimeout(() => {
        const el = document.getElementById(hash.slice(1))
        if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' })
      }, 100)
      return () => clearTimeout(timer)
    }
  }, [hash])

  return (
    <div className={`break-words overflow-wrap-anywhere ${className ?? ''}`}>
      <ReactMarkdown components={mdComponents}>{content}</ReactMarkdown>
    </div>
  )
}
