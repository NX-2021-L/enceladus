import { GraphUnavailableError, NotFoundError, SessionExpiredError } from './client'

const API_BASE = '/api/v1'

export interface GraphNode {
  record_id?: string
  title?: string
  record_type?: string
  [key: string]: unknown
}

export interface GraphEdge {
  type: string
  start: string
  end: string
}

export interface GraphNeighborsResponse {
  nodes: GraphNode[]
  edges: GraphEdge[]
  summary?: string
  error?: string
}

export const graphKeys = {
  neighbors: (projectId: string, recordId: string, edgeTypes: string) =>
    ['graph', 'neighbors', projectId, recordId, edgeTypes] as const,
}

export async function fetchGraphNeighbors(params: {
  projectId: string
  recordId: string
  edgeTypes?: string[]
  depth?: number
}): Promise<GraphNeighborsResponse> {
  const qs = new URLSearchParams({
    search_type: 'neighbors',
    project_id: params.projectId,
    record_id: params.recordId,
    depth: String(params.depth ?? 2),
  })
  if (params.edgeTypes?.length) qs.set('edge_types', params.edgeTypes.join(','))

  const url = `${API_BASE}/tracker/graphsearch?${qs.toString()}`
  const res = await fetch(url, { credentials: 'include', cache: 'no-store' })
  if (res.status === 401) throw new SessionExpiredError()
  if (res.status === 404) throw new NotFoundError(`Not found: ${url}`)
  if (res.status === 503) throw new GraphUnavailableError('Graph index temporarily unavailable')
  if (!res.ok) throw new Error(`Request failed (${res.status}): ${url}`)
  return (await res.json()) as GraphNeighborsResponse
}
