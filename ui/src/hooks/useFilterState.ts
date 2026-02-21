import { useState, useCallback } from 'react'

export function useFilterState<T extends { [K in keyof T]?: string | string[] }>(
  initial: T
) {
  const [filters, setFilters] = useState<T>(initial)

  const toggleArrayFilter = useCallback(
    (key: keyof T, value: string) => {
      setFilters((prev) => {
        const arr = (prev[key] as string[] | undefined) ?? []
        const next = arr.includes(value) ? arr.filter((v) => v !== value) : [...arr, value]
        return { ...prev, [key]: next.length ? next : undefined }
      })
    },
    []
  )

  const setFilter = useCallback(
    <K extends keyof T>(key: K, value: T[K]) => {
      setFilters((prev) => ({ ...prev, [key]: value || undefined }))
    },
    []
  )

  const clearFilters = useCallback(() => setFilters(initial), [initial])

  return { filters, toggleArrayFilter, setFilter, clearFilters }
}
