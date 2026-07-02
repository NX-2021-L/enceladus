/**
 * PrimitiveRegistry — maps each record_type to the component that renders that
 * record. The registry is the extension seam: a new primitive is added by
 * dropping a renderer and one entry here. Types are threaded through
 * RecordShapeMap so each renderer receives exactly its own record shape.
 */

import type { ComponentType } from 'react'
import type { RecordShapeMap, RecordType } from '../types/records'
import { TaskPrimitive } from './TaskPrimitive'
import { IssuePrimitive } from './IssuePrimitive'
import { FeaturePrimitive } from './FeaturePrimitive'
import { PlanPrimitive } from './PlanPrimitive'
import { LessonPrimitive } from './LessonPrimitive'
import { DocumentPrimitive } from './DocumentPrimitive'

export type PrimitiveRenderer<K extends RecordType> = ComponentType<{
  record: RecordShapeMap[K]
}>

type Registry = { [K in RecordType]: PrimitiveRenderer<K> }

export const PrimitiveRegistry: Registry = {
  task: TaskPrimitive,
  issue: IssuePrimitive,
  feature: FeaturePrimitive,
  plan: PlanPrimitive,
  lesson: LessonPrimitive,
  document: DocumentPrimitive,
}

/** Type-safe accessor: `getPrimitive('task')` is `PrimitiveRenderer<'task'>`. */
export function getPrimitive<K extends RecordType>(type: K): PrimitiveRenderer<K> {
  return PrimitiveRegistry[type]
}
