import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { ErrorState } from './ErrorState'

describe('ErrorState', () => {
  it('renders default message when custom message not supplied', () => {
    render(<ErrorState />)
    expect(screen.getByText('Failed to load data. Connect to load.')).toBeInTheDocument()
  })

  it('renders custom message when supplied', () => {
    render(<ErrorState message="Network unavailable" />)
    expect(screen.getByText('Network unavailable')).toBeInTheDocument()
  })
})
