import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { MaturityMeter, ScoreMeter, scoreBand } from './LevelMeter'

describe('LevelMeter (spec 6.5)', () => {
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

  it('bands scores at 0.7 and 0.4', () => {
    expect([0.9, 0.7, 0.5, 0.4, 0.1].map(scoreBand)).toEqual(['high', 'high', 'mid', 'mid', 'low'])
  })

  it('draws a score as a neutral meter with filled segments, not a colored number', () => {
    act(() => root.render(<ScoreMeter label="Fresh" score={0.55} />))
    const m = container.querySelector('.enc-level') as HTMLElement
    expect(m.getAttribute('data-level')).toBe('mid')
    expect(m.querySelectorAll('i[data-on]')).toHaveLength(2)
    expect(m.textContent).toContain('0.55')
    expect(m.getAttribute('style')).toBeNull()
  })

  it('draws document maturity on four segments and ignores unknown states', () => {
    act(() => root.render(<><MaturityMeter state="contextualized" /><MaturityMeter state="weird" /></>))
    const ms = container.querySelectorAll('.enc-level')
    expect(ms).toHaveLength(1)
    expect(ms[0].querySelectorAll('i')).toHaveLength(4)
    expect(ms[0].querySelectorAll('i[data-on]')).toHaveLength(3)
  })
})
