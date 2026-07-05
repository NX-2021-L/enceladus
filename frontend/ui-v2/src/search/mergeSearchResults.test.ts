import { describe, expect, it } from 'vitest'
import { searchKeys } from '../api/searchQueryOptions'
import { searchLocalKeyword } from './localKeywordSearch'
import { hybridNodesToHits, mergeSearchResults } from './mergeSearchResults'
import type { HybridGraphsearchResponse, LocalSearchRecord } from '../types/search'

const CORPUS: LocalSearchRecord[] = [
  {
    recordId: 'ENC-TSK-H68',
    recordType: 'task',
    projectId: 'enceladus',
    title: 'Gamma monitoring task',
  },
  {
    recordId: 'ENC-ISS-058',
    recordType: 'issue',
    projectId: 'enceladus',
    title: 'Auth regression',
  },
]

describe('searchLocalKeyword', () => {
  it('matches title substring instantly', () => {
    const hits = searchLocalKeyword(CORPUS, 'auth')
    expect(hits).toHaveLength(1)
    expect(hits[0]?.recordId).toBe('ENC-ISS-058')
    expect(hits[0]?.tier).toBe('local')
  })
})

describe('mergeSearchResults', () => {
  const hybridResponse: HybridGraphsearchResponse = {
    success: true,
    nodes: [
      {
        record_id: 'ENC-TSK-K21',
        title: 'PWA scaffold',
        _labels: ['Task'],
        status: 'open',
      },
      {
        record_id: 'ENC-ISS-058',
        title: 'Auth regression (graph)',
        _labels: ['Issue'],
      },
    ],
    edges: [],
    paths: [],
    summary: 'Hybrid: 2 nodes',
    query_cypher: 'hybrid/multi-signal-rrf',
    duration_ms: 42,
    per_node_fusion: {
      'ENC-TSK-K21': { fused_rank: 1, per_signal_ranks: { vector: 1 } },
      'ENC-ISS-058': { fused_rank: 2 },
    },
  }

  it('preserves local hits and adds hybrid-only rows', () => {
    const local = searchLocalKeyword(CORPUS, 'auth')
    const { hits, localCount, hybridCount } = mergeSearchResults(
      local,
      hybridResponse,
      'enceladus',
    )
    expect(localCount).toBe(1)
    expect(hybridCount).toBe(2)
    expect(hits.map((h) => h.recordId).sort()).toEqual(['ENC-ISS-058', 'ENC-TSK-K21'])
    const enriched = hits.find((h) => h.recordId === 'ENC-ISS-058')
    expect(enriched?.tier).toBe('local')
    expect(enriched?.fusion?.fused_rank).toBe(2)
  })

  it('maps hybrid nodes to hits with tier hybrid', () => {
    const hits = hybridNodesToHits('enceladus', hybridResponse)
    expect(hits[0]?.tier).toBe('hybrid')
    expect(hits[0]?.recordType).toBe('task')
  })
})

describe('searchKeys.hybrid', () => {
  it('uses the search/hybrid namespace', () => {
    expect(
      searchKeys.hybrid({ projectId: 'enceladus', query: 'deploy' }),
    ).toEqual([
      'search',
      'hybrid',
      {
        projectId: 'enceladus',
        query: 'deploy',
        anchorRecordId: '',
        recordType: '',
        topN: 20,
        includeBelowThreshold: false,
      },
    ])
  })
})
