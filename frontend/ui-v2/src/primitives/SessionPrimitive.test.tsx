import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { SessionPrimitive } from './SessionPrimitive'
import type { Session } from '../types/session'

/**
 * No @testing-library/react is installed in this package (every existing
 * ui-v2 test is logic-level, not component-level) — this is a minimal
 * createRoot + act smoke test using only what's already a dependency
 * (react-dom/client), matching the jsdom environment already configured in
 * vitest.config.ts.
 */

const BASE_SESSION: Session = {
  session_id: 'ENC-SES-0A1',
  agent_type_id: 'ENC-AGT-001',
  parent_session_id: 'root',
  runtime: 'claude-code-cli',
  status: 'claimed',
  created_at: '2026-07-02T13:00:00Z',
  claimed_at: '2026-07-02T13:00:05Z',
  updated_at: '2026-07-05T09:00:00Z',
  last_activity_at: '2026-07-05T09:00:00Z',
}

describe('SessionPrimitive', () => {
  let container: HTMLDivElement
  let root: Root

  beforeEach(() => {
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
  })

  afterEach(() => {
    act(() => root.unmount())
    container.remove()
  })

  it('renders session fields via KeyValuePairs', () => {
    act(() => {
      root.render(<SessionPrimitive record={BASE_SESSION} />)
    })
    expect(container.textContent).toContain('ENC-SES-0A1')
    expect(container.textContent).toContain('ENC-AGT-001')
    expect(container.textContent).toContain('claude-code-cli')
    expect(container.textContent).toContain('2026-07-05T09:00:00Z')
  })

  it('shows an empty state when no worklog has been mirrored', () => {
    act(() => {
      root.render(<SessionPrimitive record={BASE_SESSION} />)
    })
    expect(container.textContent).toContain('No worklog entries have been mirrored')
  })

  it('renders mirrored worklog entries in the table', () => {
    const withHistory: Session = {
      ...BASE_SESSION,
      history: [
        {
          timestamp: '2026-07-05T09:00:00Z',
          status: 'worklog',
          description: '[task:ENC-TSK-901] did the thing',
          source_record_type: 'task',
          source_record_id: 'ENC-TSK-901',
        },
        {
          timestamp: '2026-07-05T09:05:00Z',
          status: 'worklog',
          description: '[plan:ENC-PLN-001] second entry',
          source_record_type: 'plan',
          source_record_id: 'ENC-PLN-001',
        },
      ],
    }
    act(() => {
      root.render(<SessionPrimitive record={withHistory} />)
    })
    const rows = container.querySelectorAll('tbody tr')
    expect(rows.length).toBe(2)
    expect(container.textContent).toContain('task:ENC-TSK-901')
    expect(container.textContent).toContain('did the thing')
    expect(container.textContent).toContain('plan:ENC-PLN-001')
    expect(container.textContent).toContain('second entry')
  })
})
