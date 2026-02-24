interface FilterBarProps {
  options: readonly string[]
  selected: string[]
  onToggle: (value: string) => void
  labels?: Record<string, string>
  colorMap?: Record<string, string>
}

export function FilterBar({ options, selected, onToggle, labels, colorMap }: FilterBarProps) {
  return (
    <div className="flex gap-2 overflow-x-auto pb-1 scrollbar-hide">
      {options.map((opt) => {
        const isActive = selected.includes(opt)
        const activeColor = colorMap?.[opt] ?? 'bg-blue-500/20 text-blue-400'
        return (
          <button
            key={opt}
            onClick={() => onToggle(opt)}
            className={`flex-shrink-0 px-3 py-1.5 rounded-full text-xs font-medium min-h-[32px] transition-colors ${
              isActive ? activeColor : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
            }`}
          >
            {labels?.[opt] ?? opt}
          </button>
        )
      })}
    </div>
  )
}
