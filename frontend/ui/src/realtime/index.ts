/**
 * PWA 2.0 real-time architecture library (ENC-TSK-B67).
 *
 * Barrel export for the Governance Cockpit real-time layer:
 *   - eventModel:          AC-10/AC-23 feed-event contract + validator
 *   - appsyncEventsClient: AC-1/AC-4/AC-15 WebSocket transport + resilience
 *   - feedBuffer:          AC-9/AC-11 dedup + new-activities banner
 *   - entityStore:         AC-12 normalized entity layer (cross-page consistency)
 *   - uiStore:             AC-13 UI-only state ownership boundary
 *   - optimisticMutations: AC-5/AC-6/AC-7/AC-19 optimistic + conflict resolution
 *   - governanceDocs:      AC-20 live governed-docs read (no static mirror)
 *   - graphModel:          AC-21/AC-22 plan-tree + typed-rel + context-node graph
 */

export * from './eventModel'
export * from './appsyncEventsClient'
export * from './feedBuffer'
export * from './entityStore'
export * from './uiStore'
export * from './optimisticMutations'
export * from './governanceDocs'
export * from './graphModel'
