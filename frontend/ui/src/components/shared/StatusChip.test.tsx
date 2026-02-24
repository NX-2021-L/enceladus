import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { StatusChip } from './StatusChip'

describe('StatusChip', () => {
  it('renders known status label', () => {
    render(<StatusChip status="in-progress" />)
    expect(screen.getByText('In Progress')).toBeInTheDocument()
  })

  it('falls back to raw status text for unknown values', () => {
    render(<StatusChip status="custom-state" />)
    expect(screen.getByText('custom-state')).toBeInTheDocument()
  })
})
