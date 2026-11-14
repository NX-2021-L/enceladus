The loading placeholder for a feed row.

The preview is a schematic. From the catalog: the shimmer uses inline `enc-shimmer` keyframes at 1.4s, and the app has no `prefers-reduced-motion` rule.

- Use it in place of rows while a list loads; it replaces the documented `Spinner` for lists.
- Recommended: stop the shimmer under `prefers-reduced-motion: reduce`, as the preview does.

Gap: bar sizes and the number of placeholder rows.
