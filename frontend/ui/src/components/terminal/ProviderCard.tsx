import { useState } from 'react'
import type { TerminalProvider } from '../../types/terminal'

interface ProviderCardProps {
  provider: TerminalProvider
  onStartSession: (provider: TerminalProvider) => void
}

export function ProviderCard({ provider, onStartSession }: ProviderCardProps) {
  const [hovered, setHovered] = useState(false)

  return (
    <div
      className="relative bg-slate-800 border border-slate-700/50 rounded-lg p-4 transition-colors hover:border-slate-600"
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      onTouchStart={() => setHovered(true)}
      onTouchEnd={() => setTimeout(() => setHovered(false), 2000)}
    >
      <div className="flex items-center gap-3 mb-2">
        <div className="w-8 h-8 rounded-lg bg-slate-700 flex items-center justify-center text-slate-400">
          {provider.id === 'openai_codex' ? (
            <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
              <path d="M22.282 9.821a5.985 5.985 0 00-.516-4.91 6.046 6.046 0 00-6.51-2.9A6.065 6.065 0 0011.74.4 6.044 6.044 0 005.7 4.78a5.993 5.993 0 00-3.994 2.907 6.046 6.046 0 00.743 7.097 5.98 5.98 0 00.51 4.911 6.05 6.05 0 006.515 2.9A6.07 6.07 0 0013.26 23.6a6.04 6.04 0 006.04-4.38 6 6 0 003.982-2.907 6.04 6.04 0 00-1-6.492z" />
            </svg>
          ) : (
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9.75 3.104v5.714a2.25 2.25 0 01-.659 1.591L5 14.5M9.75 3.104c-.251.023-.501.05-.75.082m.75-.082a24.301 24.301 0 014.5 0m0 0v5.714c0 .597.237 1.17.659 1.591L19.8 14.5M14.25 3.104c.251.023.501.05.75.082M19.8 14.5l-2.303 2.303a2.25 2.25 0 01-1.591.659H8.094a2.25 2.25 0 01-1.591-.659L4.2 14.5" />
            </svg>
          )}
        </div>
        <div>
          <div className="text-sm font-medium text-slate-200">{provider.name}</div>
          <div className="text-xs text-slate-500">{provider.description}</div>
        </div>
      </div>

      {hovered && (
        <button
          onClick={() => onStartSession(provider)}
          className="w-full mt-2 py-1.5 px-3 bg-purple-600/20 border border-purple-500/30 rounded-lg text-xs text-purple-300 hover:bg-purple-600/30 transition-colors"
        >
          Start New Session
        </button>
      )}
    </div>
  )
}
