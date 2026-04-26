/**
 * Unit tests for the ENC-FTR-073 Phase 2c UX primitives (ENC-TSK-D96):
 *   - RecordFallbackLoading
 *   - RecordNotFound
 *   - RecordFallbackError
 *
 * Assertions focus on accessibility and props-driven rendering — these
 * components are pure presentational, so the tests serve as the visual
 * reference required by AC6 (Storybook or equivalent).
 */

import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import { RecordFallbackError } from './RecordFallbackError'
import { RecordFallbackLoading } from './RecordFallbackLoading'
import { RecordNotFound } from './RecordNotFound'

describe('RecordFallbackLoading', () => {
  it('sets aria-busy=true and role=status for screen readers', () => {
    render(<RecordFallbackLoading />)
    const container = screen.getByRole('status')
    expect(container).toHaveAttribute('aria-busy', 'true')
    expect(container).toHaveAttribute('aria-live', 'polite')
  })

  it('renders the default label as SR-only text', () => {
    render(<RecordFallbackLoading />)
    expect(screen.getByText('Loading record...')).toBeInTheDocument()
  })

  it('accepts a custom label', () => {
    render(<RecordFallbackLoading label="Fetching plan" />)
    expect(screen.getByText('Fetching plan')).toBeInTheDocument()
  })
})

describe('RecordNotFound', () => {
  function withRouter(ui: React.ReactElement) {
    return <MemoryRouter>{ui}</MemoryRouter>
  }

  it('surfaces the attempted record ID and type in the detail copy', () => {
    render(withRouter(<RecordNotFound recordType="plan" recordId="ENC-PLN-006" />))
    expect(screen.getByRole('heading', { name: /record not found/i })).toBeInTheDocument()
    expect(screen.getByText('ENC-PLN-006')).toBeInTheDocument()
    expect(screen.getByText(/No plan with ID/i)).toBeInTheDocument()
  })

  it('links back to the type index page', () => {
    render(withRouter(<RecordNotFound recordType="lesson" recordId="ENC-LSN-001" />))
    const link = screen.getByRole('link', { name: /back to lessons/i })
    expect(link).toHaveAttribute('href', '/lessons')
  })

  it('is announced as a polite live region', () => {
    render(withRouter(<RecordNotFound recordType="task" recordId="ENC-TSK-1" />))
    const region = screen.getByRole('status')
    expect(region).toHaveAttribute('aria-live', 'polite')
  })
})

describe('RecordFallbackError', () => {
  it('renders an alert-role region with assertive announcement', () => {
    render(<RecordFallbackError />)
    const region = screen.getByRole('alert')
    expect(region).toHaveAttribute('aria-live', 'assertive')
  })

  it('renders the default message when none is supplied', () => {
    render(<RecordFallbackError />)
    expect(
      screen.getByText(/we could not load this record\. check your connection/i),
    ).toBeInTheDocument()
  })

  it('renders the Retry button only when onRetry is provided', async () => {
    const onRetry = vi.fn()
    render(<RecordFallbackError onRetry={onRetry} />)
    const button = screen.getByRole('button', { name: /retry/i })
    await userEvent.click(button)
    expect(onRetry).toHaveBeenCalledTimes(1)
  })

  it('omits the Retry button when onRetry is undefined', () => {
    render(<RecordFallbackError />)
    expect(screen.queryByRole('button', { name: /retry/i })).not.toBeInTheDocument()
  })
})
