# PWA 2.0 Governance Cockpit — UI Kit

A pixel-faithful recreation of the Enceladus PWA frontend, a **mobile-first dark** governance cockpit used daily by the sole operator to monitor 20+ projects, 2,789+ governed records, and live agent sessions.

## Source of truth

- `NX-2021-L/enceladus` · `frontend/ui/src/` (React 19 + Vite + Tailwind)
- Components directly referenced: `Header.tsx`, `BottomNav.tsx`, `TaskRow.tsx`, `LessonRow.tsx`, `ProjectCard.tsx`, `CheckoutStateBadge.tsx`, `ActiveSessionBadge.tsx`, `StatusChip`, `PriorityBadge`.

## What's in here

- `index.html` — a single self-contained interactive click-thru prototype. Home → Projects → Feed → Docs → Changelog via the sticky bottom nav. Tap the ☰ hamburger for the overflow menu. Stats are live-plausible; data is fixture. All components (Header, BottomNav, the feed-row cards, badges, and the five screens) plus the fixture data are inlined in one `<script type="text/babel">` block — nothing external to load.

## Notes

- Tailwind is loaded from the Play CDN. Production uses a local build. Colors map 1:1 to production's `slate-*` / `blue-*` / `amber-*` / `purple-*` classes — the PWA predates the formal brand-token migration (see `colors_and_type.css` for the updated `enc-*` vocabulary).
- `react-router-dom` is stubbed — navigation is a `useState` in `index.html`.
- Icons are inline `<svg>` paths copied from production (single stroke, `stroke-width={1.5-2}`).
