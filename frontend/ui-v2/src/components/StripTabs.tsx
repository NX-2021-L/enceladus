import { useLayoutEffect, useRef, type ComponentProps } from 'react'
import { useOverflowEdges } from '@io-kit/shell/react'
import { Tabs as DsTabs } from '../design-system'
import './strips.css'

/**
 * DVP-TSK-A09 (R16): ds2 Tabs whose bar is a horizontal STRIP (.io-scroll-x): overflow-y hidden, never a scrollbar,
 * edge fades where the tabs continue (kit useOverflowEdges), the active tab kept in view.
 */
export function Tabs(props: ComponentProps<typeof DsTabs>) {
  const wrapRef = useRef<HTMLDivElement | null>(null)
  const barRef = useRef<HTMLElement | null>(null)
  useLayoutEffect(() => {
    const bar = wrapRef.current?.querySelector<HTMLElement>('.ev2-tabs__bar') ?? null
    bar?.classList.add('io-scroll-x')
    barRef.current = bar
    const active = bar?.querySelector<HTMLElement>('[aria-selected="true"]')
    active?.scrollIntoView?.({ block: 'nearest', inline: 'nearest' })
  })
  useOverflowEdges(barRef)
  return (
    <div ref={wrapRef} className="ev2-tabs-strip">
      <DsTabs {...props} />
    </div>
  )
}
