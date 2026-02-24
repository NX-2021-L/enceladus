export interface TaskFilters {
  projectId?: string
  status?: string[]
  priority?: string[]
  search?: string
  sortBy?: string
}

export interface IssueFilters {
  projectId?: string
  status?: string[]
  severity?: string[]
  search?: string
  sortBy?: string
}

export interface FeatureFilters {
  projectId?: string
  status?: string[]
  search?: string
  sortBy?: string
}

export interface DocumentFilters {
  projectId?: string
  status?: string[]
  search?: string
  sortBy?: string
}

export interface FeedFilters {
  projectId?: string
  recordType?: string[]
  status?: string[]
  priority?: string[]
  severity?: string[]
  search?: string
  sortBy?: string
}

export interface CoordinationFilters {
  state?: string[]
  projectId?: string
  search?: string
  sortBy?: string
}
