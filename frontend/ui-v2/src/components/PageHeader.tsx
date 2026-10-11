import type { ReactNode } from 'react'
import { Header } from '../design-system'
import './pageHeader.css'

export interface PageHeaderProps {
  title: ReactNode
  /** Appended in the muted style: 5573 -> "Feed (5,573)"; a string is shown as given inside the parentheses. */
  count?: number | string
  description?: ReactNode
  actions?: ReactNode
  /** Small inline control right after the count (e.g. the search "hide toggles" link). Part of the title row, not the heading text. */
  meta?: ReactNode
}

/**
 * DVP-TSK-A09 (R16): the ONE page header for every route. h1 in the ds2 `.ev2-header__title` type, the same top and
 * left edge as the content, the count muted, and one fixed gap to the first component below it.
 */
export function PageHeader({ title, count, description, actions, meta }: PageHeaderProps) {
  const counter = count === undefined ? undefined : `(${typeof count === 'number' ? count.toLocaleString('en-US') : count})`
  return (
    <div className="ev2-page-header" data-page-header="">
      <Header
        variant="h1"
        {...(counter && !meta ? { counter } : {})}
        {...(description ? { description } : {})}
        {...(actions ? { actions } : {})}
      >
        {title}
        {counter ? ' ' : null}
        {/* With a meta control the count is rendered here (same class) so the control follows it in the title row. */}
        {counter && meta ? <span className="ev2-header__counter">{counter}</span> : null}
        {meta ? <span className="ev2-page-header__meta">{meta}</span> : null}
      </Header>
    </div>
  )
}
