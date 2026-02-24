import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { FilterBar } from './FilterBar'

describe('FilterBar', () => {
  it('renders labels and calls onToggle', () => {
    const onToggle = vi.fn()
    render(
      <FilterBar
        options={['open', 'closed']}
        selected={['open']}
        onToggle={onToggle}
        labels={{ open: 'Open', closed: 'Closed' }}
      />,
    )

    fireEvent.click(screen.getByRole('button', { name: 'Closed' }))
    expect(onToggle).toHaveBeenCalledWith('closed')
  })
})
