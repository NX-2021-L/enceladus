import { MarkdownRenderer } from '../shared/MarkdownRenderer'

interface MessageBubbleProps {
  role: 'user' | 'assistant'
  content: string
  timestamp?: string
}

export function MessageBubble({ role, content, timestamp }: MessageBubbleProps) {
  const isUser = role === 'user'

  return (
    <div className={`flex ${isUser ? 'justify-end' : 'justify-start'} mb-3`}>
      <div
        className={`max-w-[85%] rounded-lg px-3 py-2 ${
          isUser
            ? 'bg-purple-600/30 border border-purple-500/30 text-slate-100'
            : 'bg-slate-800 border border-slate-700/50 text-slate-200'
        }`}
      >
        {isUser ? (
          <p className="text-sm whitespace-pre-wrap break-words">{content}</p>
        ) : (
          <div className="text-sm">
            <MarkdownRenderer content={content} />
          </div>
        )}
        {timestamp && (
          <div className={`text-[10px] mt-1 ${isUser ? 'text-purple-300/60' : 'text-slate-500'}`}>
            {new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
          </div>
        )}
      </div>
    </div>
  )
}
