interface SortOption {
  readonly value: string
  readonly label: string
}

interface SortPickerProps {
  options: readonly SortOption[]
  active: string
  onChange: (value: string) => void
}

function parseSort(active: string): { field: string; dir: 'asc' | 'desc' } {
  const [field, dir] = active.split(':')
  return { field, dir: dir === 'asc' ? 'asc' : 'desc' }
}

export function SortPicker({ options, active, onChange }: SortPickerProps) {
  const { field, dir } = parseSort(active)

  function handleClick(value: string) {
    if (value === field) {
      onChange(`${value}:${dir === 'desc' ? 'asc' : 'desc'}`)
    } else {
      onChange(`${value}:desc`)
    }
  }

  return (
    <div className="flex items-center gap-2">
      <span className="text-xs text-slate-500 flex-shrink-0">Sort:</span>
      <div className="flex gap-1.5 overflow-x-auto scrollbar-hide">
        {options.map((opt) => {
          const isActive = opt.value === field
          return (
            <button
              key={opt.value}
              onClick={() => handleClick(opt.value)}
              className={`flex-shrink-0 px-2.5 py-1 rounded-full text-xs font-medium min-h-[28px] transition-colors ${
                isActive
                  ? 'bg-blue-500/20 text-blue-400'
                  : 'bg-slate-800 text-slate-400 hover:text-slate-300'
              }`}
            >
              {opt.label}
              {isActive && (
                <span className="ml-1">{dir === 'desc' ? '↓' : '↑'}</span>
              )}
            </button>
          )
        })}
      </div>
    </div>
  )
}
