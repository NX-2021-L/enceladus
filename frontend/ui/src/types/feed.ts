import type { Task, Issue, Feature, Lesson } from './feeds'

export type RecordType = 'task' | 'issue' | 'feature' | 'lesson'

export type FeedItem =
  | { _type: 'task'; _id: string; _updated_at: string | null; _created_at: string | null; data: Task }
  | { _type: 'issue'; _id: string; _updated_at: string | null; _created_at: string | null; data: Issue }
  | { _type: 'feature'; _id: string; _updated_at: string | null; _created_at: string | null; data: Feature }
  | { _type: 'lesson'; _id: string; _updated_at: string | null; _created_at: string | null; data: Lesson }
