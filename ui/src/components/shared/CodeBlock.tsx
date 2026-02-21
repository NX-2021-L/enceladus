import { Light as SyntaxHighlighter } from 'react-syntax-highlighter'
import json from 'react-syntax-highlighter/dist/esm/languages/hljs/json'
import yaml from 'react-syntax-highlighter/dist/esm/languages/hljs/yaml'
import sql from 'react-syntax-highlighter/dist/esm/languages/hljs/sql'
import xml from 'react-syntax-highlighter/dist/esm/languages/hljs/xml'
import css from 'react-syntax-highlighter/dist/esm/languages/hljs/css'
import javascript from 'react-syntax-highlighter/dist/esm/languages/hljs/javascript'
import typescript from 'react-syntax-highlighter/dist/esm/languages/hljs/typescript'
import python from 'react-syntax-highlighter/dist/esm/languages/hljs/python'
import bash from 'react-syntax-highlighter/dist/esm/languages/hljs/bash'
import markdown from 'react-syntax-highlighter/dist/esm/languages/hljs/markdown'
import ini from 'react-syntax-highlighter/dist/esm/languages/hljs/ini'
import dockerfile from 'react-syntax-highlighter/dist/esm/languages/hljs/dockerfile'
import { stackoverflowDark } from 'react-syntax-highlighter/dist/esm/styles/hljs'

// Register languages for tree-shaking (Light build only includes what we register)
SyntaxHighlighter.registerLanguage('json', json)
SyntaxHighlighter.registerLanguage('yaml', yaml)
SyntaxHighlighter.registerLanguage('yml', yaml)
SyntaxHighlighter.registerLanguage('sql', sql)
SyntaxHighlighter.registerLanguage('xml', xml)
SyntaxHighlighter.registerLanguage('html', xml)
SyntaxHighlighter.registerLanguage('css', css)
SyntaxHighlighter.registerLanguage('javascript', javascript)
SyntaxHighlighter.registerLanguage('js', javascript)
SyntaxHighlighter.registerLanguage('typescript', typescript)
SyntaxHighlighter.registerLanguage('ts', typescript)
SyntaxHighlighter.registerLanguage('tsx', typescript)
SyntaxHighlighter.registerLanguage('python', python)
SyntaxHighlighter.registerLanguage('py', python)
SyntaxHighlighter.registerLanguage('bash', bash)
SyntaxHighlighter.registerLanguage('sh', bash)
SyntaxHighlighter.registerLanguage('shell', bash)
SyntaxHighlighter.registerLanguage('markdown', markdown)
SyntaxHighlighter.registerLanguage('md', markdown)
SyntaxHighlighter.registerLanguage('ini', ini)
SyntaxHighlighter.registerLanguage('toml', ini)
SyntaxHighlighter.registerLanguage('dockerfile', dockerfile)

/** Map file extensions to highlight.js language keys */
const EXT_TO_LANG: Record<string, string> = {
  json: 'json',
  yaml: 'yaml',
  yml: 'yaml',
  sql: 'sql',
  html: 'html',
  htm: 'html',
  xml: 'xml',
  svg: 'xml',
  css: 'css',
  js: 'javascript',
  mjs: 'javascript',
  cjs: 'javascript',
  jsx: 'javascript',
  ts: 'typescript',
  tsx: 'typescript',
  py: 'python',
  sh: 'bash',
  bash: 'bash',
  zsh: 'bash',
  md: 'markdown',
  ini: 'ini',
  toml: 'toml',
  env: 'ini',
  dockerfile: 'dockerfile',
}

/** Pretty display labels for language badges */
const LANG_LABELS: Record<string, string> = {
  json: 'JSON',
  yaml: 'YAML',
  yml: 'YAML',
  sql: 'SQL',
  html: 'HTML',
  xml: 'XML',
  css: 'CSS',
  javascript: 'JavaScript',
  js: 'JavaScript',
  typescript: 'TypeScript',
  ts: 'TypeScript',
  tsx: 'TSX',
  python: 'Python',
  py: 'Python',
  bash: 'Bash',
  sh: 'Shell',
  shell: 'Shell',
  markdown: 'Markdown',
  md: 'Markdown',
  ini: 'INI',
  toml: 'TOML',
  dockerfile: 'Dockerfile',
}

/**
 * Detect language from a file name extension.
 * Returns the highlight.js language key or undefined.
 */
export function detectLanguageFromFilename(filename: string): string | undefined {
  // Handle "Dockerfile" with no extension
  if (filename.toLowerCase() === 'dockerfile') return 'dockerfile'
  const ext = filename.split('.').pop()?.toLowerCase()
  return ext ? EXT_TO_LANG[ext] : undefined
}

interface CodeBlockProps {
  /** Source code to render */
  code: string
  /** Language key (from markdown fenced code or file detection) */
  language?: string
  /** Show a language label badge */
  showLabel?: boolean
  /** Enable word wrap (default: true) */
  wrapLines?: boolean
}

export function CodeBlock({ code, language, showLabel = true, wrapLines = true }: CodeBlockProps) {
  const label = language ? LANG_LABELS[language] ?? language : undefined

  return (
    <div className="relative rounded-lg overflow-hidden mb-3">
      {showLabel && label && (
        <div className="flex justify-end bg-slate-900/80 px-3 py-1 border-b border-slate-700/50">
          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500">
            {label}
          </span>
        </div>
      )}
      <SyntaxHighlighter
        language={language}
        style={stackoverflowDark}
        customStyle={{
          margin: 0,
          padding: '0.75rem',
          background: 'rgb(30 41 59)', // slate-800
          fontSize: '0.75rem',
          lineHeight: '1.5',
          borderRadius: showLabel && label ? '0 0 0.5rem 0.5rem' : '0.5rem',
        }}
        wrapLongLines={wrapLines}
        showLineNumbers={false}
      >
        {code}
      </SyntaxHighlighter>
    </div>
  )
}
