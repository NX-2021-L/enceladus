import { useNavigate } from 'react-router-dom'

export function ManageConnectionButton() {
  const navigate = useNavigate()

  return (
    <button
      onClick={() => navigate('/terminal/manage')}
      className="shrink-0 w-8 h-8 flex items-center justify-center rounded-full bg-slate-700 hover:bg-slate-600 text-slate-400 hover:text-slate-200 transition-colors"
      title="Manage terminal connection"
      aria-label="Manage terminal connection"
    >
      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          d="M6.75 7.5l3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0021 18V6a2.25 2.25 0 00-2.25-2.25H5.25A2.25 2.25 0 003 6v12a2.25 2.25 0 002.25 2.25z"
        />
      </svg>
    </button>
  )
}
