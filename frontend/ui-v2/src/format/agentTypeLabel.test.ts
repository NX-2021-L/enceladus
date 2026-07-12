import { describe, expect, it } from 'vitest'
import type { AgentType } from '../api/coordination'
import {
  formatAgentTypeSecondary,
  formatSessionCardDescription,
} from './agentTypeLabel'

const agentType: AgentType = {
  agent_type_id: 'ENC-AGT-003',
  surface: 'Claude Desktop',
  model: 'Opus 4.8',
  cost_tier: 'premium',
  status: 'active',
  usage_count: 2,
}

describe('formatAgentTypeSecondary', () => {
  it('joins governed id with roster surface/model', () => {
    expect(formatAgentTypeSecondary('ENC-AGT-003', agentType)).toBe(
      'ENC-AGT-003 · Claude Desktop / Opus 4.8',
    )
  })

  it('returns the governed id alone when the roster row is missing', () => {
    expect(formatAgentTypeSecondary('ENC-AGT-005')).toBe('ENC-AGT-005')
  })

  it('does not uppercase or substitute legacy raw ids', () => {
    expect(formatAgentTypeSecondary('desktop')).toBe('desktop')
  })
})

describe('formatSessionCardDescription', () => {
  it('keeps runtime as a separate trailing segment', () => {
    expect(formatSessionCardDescription('ENC-AGT-003', 'cc-desktop', agentType)).toBe(
      'ENC-AGT-003 · Claude Desktop / Opus 4.8 · Runtime: cc-desktop',
    )
  })
})
