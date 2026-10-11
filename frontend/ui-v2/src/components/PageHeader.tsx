import type { ReactNode } from 'react'
import { Header } from '../design-system'
import './pageHeader.css'

export interface PageHeaderProps {
  title: ReactNode
  /** Appended in the muted style: 5573 -> "Feed (5,573)"; a string is shown as given inside the parentheses. */
  count?: number | string
  description?: ReactNode
  actions?: ReactNode
}

/**
 * DVP-TSK-A09 (R16): the ONE page header for every route. h1 in the ds2 `.ev2-header__title` type, the same top and
 * left edge as the content, the count muted, and one fixed gap to the first component below it.
 */
export function PageHeader({ title, count, description, actions }: PageHeaderProps) {
  const counter = count === undefined ? undefined : `(${typeof count === 'number' ? count.toLocaleString('en-US') : count})`
  return (
    <div className="ev2-page-header" data-page-header="">
      <Header
        variant="h1"
        {...(counter ? { counter } : {})}
        {...(description ? { description } : {})}
        {...(actions ? { actions } : {})}
      >
        {title}
        {counter ? ' ' : null}
      </Header>
    </div>
  )
}
