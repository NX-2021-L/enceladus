import { useLayoutEffect, useRef } from 'react'
import { useOverflowEdges } from '@io-kit/shell/react'
import { Table as DsTable } from '../design-system'
import './strips.css'

/**
 * DVP-TSK-A09 (R16): ds2 Table with two phone/tablet behaviours. Below 688px the rows stack (label / value per cell,
 * see strips.css), so there is no horizontal scroll. Wider, any remaining horizontal scroll is a strip (.io-scroll-x:
 * no bar, edge fades). Each cell gets data-label from its column header.
 */
export function Table<T>(props: Parameters<typeof DsTable<T>>[0]) {
  const wrapRef = useRef<HTMLDivElement | null>(null)
  const scrollRef = useRef<HTMLElement | null>(null)
  useLayoutEffect(() => {
    const root = wrapRef.current
    if (!root) return
    const scroll = root.querySelector<HTMLElement>('.ev2-table__scroll')
    scroll?.classList.add('io-scroll-x')
    scrollRef.current = scroll
    const labels = Array.from(root.querySelectorAll('thead th')).map((th) => {
      const clone = th.cloneNode(true) as HTMLElement
      clone.querySelector('.ev2-table__sortarrow')?.remove()
      return (clone.textContent ?? '').trim()
    })
    root.querySelectorAll('tbody tr').forEach((tr) => {
      Array.from(tr.children).forEach((td, i) => {
        if (td.classList.contains('ev2-table__empty') || td.classList.contains('ev2-table__sel')) return
        td.setAttribute('data-label', labels[i] ?? '')
      })
    })
  })
  useOverflowEdges(scrollRef)
  return (
    <div ref={wrapRef} className="ev2-table-stack">
      <DsTable<T> {...props} />
    </div>
  )
}
