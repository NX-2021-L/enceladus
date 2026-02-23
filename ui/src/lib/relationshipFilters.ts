/**
 * relationshipFilters.ts
 *
 * Utility functions for filtering relationships to prevent duplication
 * between hierarchy (parent/children) and related items sections.
 *
 * ENC-FTR-014: PWA task hierarchy UX — separate hierarchical relationships
 * from related items
 */

/**
 * Filter related item IDs to exclude parent and children.
 *
 * Ensures no item appears in both hierarchy and related items sections.
 *
 * @param relatedIds - Array of related item IDs to filter
 * @param parentId - The parent ID (if any)
 * @param childrenIds - Array of children IDs (from parent field filtering)
 * @returns Filtered array with parent and children removed
 */
export function filterRelatedItems(
  relatedIds: string[],
  parentId: string | null | undefined,
  childrenIds: string[]
): string[] {
  // Build set of IDs to exclude (parent + all children)
  const excludeSet = new Set<string>();

  if (parentId) {
    excludeSet.add(parentId);
  }

  childrenIds.forEach(id => excludeSet.add(id));

  // Filter out excluded IDs
  return relatedIds.filter(id => !excludeSet.has(id));
}

/**
 * Get all children IDs for a given record ID.
 *
 * Scans all items and returns those with parent === recordId.
 *
 * @param recordId - The parent record ID to find children for
 * @param allItems - All items (tasks, issues, or features)
 * @returns Array of child IDs
 */
export function getChildrenIds(
  recordId: string,
  allItems: Array<any> // Task | Issue | Feature
): string[] {
  return allItems
    .filter(item => item.parent === recordId)
    .map(item => item.task_id || item.issue_id || item.feature_id)
    .filter((id): id is string => Boolean(id));
}
