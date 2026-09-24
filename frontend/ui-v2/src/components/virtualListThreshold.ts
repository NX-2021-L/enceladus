/**
 * ENC-TSK-M18 (perf budget, AC-3): shared "when do we virtualize" rule.
 *
 * Kept as a standalone pure function (no React, no @tanstack/react-virtual
 * import) so it stays trivially unit-testable and can be reused by any list
 * surface (Feed, Coordination, Projects, Home) to decide whether to pay the
 * windowing cost at all — small lists render every row directly, which is
 * both simpler and avoids virtualizer measurement overhead for the common
 * case where a list never gets long enough to matter.
 */
export const VIRTUALIZE_ROW_THRESHOLD = 30

export function shouldVirtualize(itemCount: number): boolean {
  return itemCount > VIRTUALIZE_ROW_THRESHOLD
}
