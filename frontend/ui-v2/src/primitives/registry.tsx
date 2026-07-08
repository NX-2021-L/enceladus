/**
 * PrimitiveRegistry — maps each record_type to the component that renders that
 * record. The registry is the extension seam: a new primitive is added by
 * dropping a renderer and one entry here. Types are threaded through
 * RecordShapeMap so each renderer receives exactly its own record shape.
 *
 * ENC-TSK-M18 (perf budget): renderers are lazy-loaded via `React.lazy` —
 * `PlanPrimitive` alone pulls in `PlanGraphExplorer` -> `cytoscape` (a large
 * dependency), and none of the six primitives are needed on the routes that
 * dominate the initial paint (Home/Feed/Coordination/Projects). Every
 * `createRecordRoute` caller already wraps its component in a route-level
 * `<Suspense fallback={<SkeletonCard />}>` (see routes/recordRoute.tsx), so
 * this is a drop-in swap — no new Suspense boundary needed.
 */

import { lazy, type ComponentType } from 'react'
import type { RecordShapeMap, RecordType } from '../types/records'

export type PrimitiveRenderer<K extends RecordType> = ComponentType<{
  record: RecordShapeMap[K]
}>

type Registry = { [K in RecordType]: PrimitiveRenderer<K> }

export const PrimitiveRegistry: Registry = {
  task: lazy(() => import('./TaskPrimitive').then((m) => ({ default: m.TaskPrimitive }))),
  issue: lazy(() => import('./IssuePrimitive').then((m) => ({ default: m.IssuePrimitive }))),
  feature: lazy(() =>
    import('./FeaturePrimitive').then((m) => ({ default: m.FeaturePrimitive })),
  ),
  plan: lazy(() => import('./PlanPrimitive').then((m) => ({ default: m.PlanPrimitive }))),
  lesson: lazy(() => import('./LessonPrimitive').then((m) => ({ default: m.LessonPrimitive }))),
  document: lazy(() =>
    import('./DocumentPrimitive').then((m) => ({ default: m.DocumentPrimitive })),
  ),
}

/** Type-safe accessor: `getPrimitive('task')` is `PrimitiveRenderer<K>`. */
export function getPrimitive<K extends RecordType>(type: K): PrimitiveRenderer<K> {
  return PrimitiveRegistry[type]
}
