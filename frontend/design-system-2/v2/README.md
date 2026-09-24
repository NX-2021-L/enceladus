# Enceladus v2 — Cloudscape-based Component Library

**v2.0 · July 2026 · Dark only.**
Every component from [Cloudscape Design System](https://cloudscape.design/components/) rebuilt with the Enceladus brand — not a re-skin. Enceladus radii (3/4/6/8/12), orbital easing (`cubic-bezier(0.4,0,0.2,1)`), teal-alpha borders, JetBrains Mono telemetry decoration (record IDs, tabular scores), and the "success is teal, never green" rule are applied at the component-vocabulary level.

## Consuming

Components compile into the design-system bundle and are exposed on the project namespace:

```js
const { Button, Alert, StatusIndicator } = window.EnceladusDesignSystem_7eb1fe;
```

Tokens: `v2/tokens.css` (component layer) extends the v1 brand tokens in `colors_and_type.css`. Both load via root `styles.css`.

## Deep-rebrand conventions (applied to every component)

- **Success = Cosmic Teal `#3D9BA8`**, never green. Warning is muted amber `#C9A15C`, error crimson `#C85060`, pending lavender `#8A8CB5`.
- **`recordId` prop** on Button, Header, Flashbar (growing set): renders a JetBrains Mono teal record ID — telemetry as decoration.
- **Type**: Space Grotesk for headings/buttons, Inter body, JetBrains Mono for status labels, counters, percentages (tabular-nums).
- **Motion**: 150/200/300ms orbital easing. Pulse (opacity) for in-progress; linear rotation for spinners. `prefers-reduced-motion` respected.
- **Surfaces**: `#111827` panels on `#0A0A0F` void; borders teal-alpha 0.2 → 0.4 on hover; no shadow lift on grounded cards.
- **Focus**: 2px teal-alpha ring (`--v2-focus-ring`).

## Phase status

| Phase | Components | Status |
|---|---|---|
| 1 · Primitives | Badge, Button, Link, StatusIndicator, Spinner, Alert, Flashbar, Container, Header, Box, ProgressBar, SpaceBetween | ✅ shipped |
| 2 · Forms | Input, Textarea, FormField, Checkbox, Toggle, RadioGroup, Tiles, Select, Multiselect, Autosuggest, SegmentedControl, Slider, TokenGroup, PromptInput, Form, FileUpload, AttributeEditor, DatePicker | ✅ shipped |
| 3 · Collections | Table, Cards, Pagination, TextFilter, PropertyFilter, CollectionPreferences | ✅ shipped |
| 4 · Nav + layout | AppLayout, TopNavigation, SideNavigation, BreadcrumbGroup, Tabs, Wizard, Steps, ExpandableSection, ColumnLayout, Grid, ContentLayout, SplitPanel, HelpPanel, Drawer | ✅ shipped |
| 5 · Overlays | Modal, Popover, ButtonDropdown, ButtonGroup, ToggleButton, CopyToClipboard, KeyValuePairs, Hotspot, TutorialPanel, LiveRegion | ✅ shipped |
| 6 · Charts | BarChart, LineChart, PieChart, AreaChart, MixedChart | ✅ shipped |

All six phases complete — the full Cloudscape catalog, deep re-branded, 65 components.

## Shipped component index

Compiled onto `window.EnceladusDesignSystem_7eb1fe`:

- **Phase 1 · Primitives:** Alert, Badge, Box, Button, Container, Flashbar, Header, Link, ProgressBar, SpaceBetween, Spinner, StatusIndicator
- **Phase 2 · Forms:** AttributeEditor, Autosuggest, Checkbox, DatePicker, FileUpload, Form, FormField, Input, Multiselect, PromptInput, RadioGroup, SegmentedControl, Select, Slider, Textarea, Tiles, Toggle, TokenGroup
- **Phase 3 · Collections:** Cards, CollectionPreferences, Pagination, PropertyFilter, Table, TextFilter
- **Phase 4 · Nav + layout:** AppLayout, BreadcrumbGroup, ColumnLayout, ContentLayout, Drawer, ExpandableSection, Grid, HelpPanel, SideNavigation, SplitPanel, Steps, Tabs, TopNavigation, Wizard
- **Phase 5 · Overlays:** ButtonDropdown, ButtonGroup, CopyToClipboard, Hotspot, KeyValuePairs, LiveRegion, Modal, Popover, ToggleButton, TutorialPanel
- **Phase 6 · Charts:** AreaChart, BarChart, LineChart, MixedChart, PieChart

## Layout per component

```
v2/components/<Name>/
  <Name>.jsx     ← implementation (self-contained; injects its own scoped CSS)
  <Name>.d.ts    ← typed props contract (Cloudscape-compatible where sensible)
  <name>.html    ← @dsCard preview (group "v2 · …")
```

## Source references

- Cloudscape docs: https://cloudscape.design/components/
- Cloudscape source: `cloudscape-design/components` on GitHub (prop naming follows their API where it doesn't fight the brand — e.g. `variant`, `items`, `dismissible`, `onDismiss`).
- Deviations: no light mode; icon system remains Lucide-style strokes; `recordId` telemetry props are Enceladus-only additions.
