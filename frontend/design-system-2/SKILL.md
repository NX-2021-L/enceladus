---
name: enceladus-design
description: Enceladus design system — brand identity, visual tokens, UI components, and copy voice for the Enceladus knowledge-governance platform (PWA cockpit, jreese.net showcase, hiring docs). Use when designing, writing, or building any Enceladus-branded surface.
license: Proprietary
---

# Enceladus Design System

This skill bundles the **Enceladus brand + visual system v1.0 (April 2026)** so an agent can design, write, or build any Enceladus-branded artefact without reading the 10-section source brand doc.

## When to use

Invoke this skill for any of:

- Designing / mocking a new screen in the **PWA 2.0 governance cockpit** (mobile-first React)
- Editing the **public showcase** at `jreese.net/enceladus-showcase`
- Writing **hiring / collaborator** one-pagers or resumes about Enceladus
- Generating **copy** that references Enceladus, its primitives (Features, Tasks, Issues, Lessons), or record IDs
- Choosing **colors, type, icons, or layout** for anything downstream of Enceladus

Do NOT use this skill for generic web design, other projects by J. Reese, or anything where the user has not explicitly invoked the Enceladus brand.

## What's in the bundle

```
README.md              ← Brand overview, products, sources, content + visual rules
colors_and_type.css    ← 6 core colors + semantic tokens + 4 font families as CSS vars
assets/                ← Moon photo, favicons, showcase screenshots
preview/               ← 23 review cards (colors, type, spacing, components, brand)
ui_kits/
  showcase/            ← jreese.net site recreation — React + inline styles
  pwa/                 ← PWA governance cockpit recreation — React + Tailwind
```

## Procedure

1. **Read `README.md` first.** Sections `01 · Content fundamentals` and `02 · Visual foundations` are load-bearing. The voice rules are the most frequently violated.
2. **Import tokens, don't copy hex codes.** Either `@import 'colors_and_type.css'` or copy the `:root { --enc-* }` block verbatim. Never hard-code `#3D9BA8` — write `var(--enc-teal)`.
3. **When writing copy, check the Content Fundamentals checklist:**
   - First-person singular ("I", never "we")
   - Inline-cite record IDs in prose: `ENC-FTR-052` in JetBrains Mono
   - Exact decimal scores, not adjectives (`0.82`, not "high")
   - No emoji. No "leverage," "revolutionary," "🚀"
4. **When building UI:**
   - Start from the closest `ui_kits/` recreation — don't design from scratch
   - Dark canvas `#0A0A0F`, teal-alpha borders, 8px card radii, `cubic-bezier(0.4,0,0.2,1)` easing
   - Lucide icons at `stroke-width="1.5"`, never filled
5. **Preview cards in `preview/`** are the design-review source of truth. When uncertain ("does this chip look right?"), open the matching card and match it.

## The Five Laws (apply in order)

1. **Dark canvas, luminous signal** — void background, content emerges like starlight
2. **Fracture as detail** — governance hashes, scores, TTLs are the texture, not noise
3. **Subsurface depth** — lead with the gesture, reveal complexity on demand
4. **Orbital motion, not spring physics** — `cubic-bezier(0.4, 0, 0.2, 1)`, no bounce
5. **Telemetry is decoration** — record IDs in hiring docs aren't leakage; they're evidence

## Tokens quick reference

```css
/* Core palette — the 6 you must memorize */
--enc-void:        #0A0A0F;   /* canvas */
--enc-teal:        #3D9BA8;   /* primary brand */
--enc-seafoam:     #C8DDD9;   /* display text on dark */
--enc-lavender:    #8A8CB5;   /* knowledge + lessons */
--enc-crimson:     #C85060;   /* alerts, P0 */
--enc-slate:       #2E4D5C;   /* code, muted */

/* Type */
--font-display: 'Syne', sans-serif;        /* hero only */
--font-head:    'Space Grotesk', sans-serif; /* headings, chips */
--font-body:    'Inter', sans-serif;         /* paragraphs */
--font-mono:    'JetBrains Mono', monospace; /* IDs, scores, hex */
```

## Caveats

- No finalized logomark — use the **`ENCELADUS`** wordmark in Space Grotesk Bold ALL CAPS, tracking `0.15em`.
- Icons are Lucide, not byte-identical to PWA-shipped paths. Substitute freely; silhouettes match.
- Fonts load from Google Fonts CDN; no offline/print font files ship in this bundle.
- Showcase kit uses CDN Bootstrap 5 for outer nav reset — the live site loads `jreese.net/css/styles.css` which is not included.

## Authorship

This skill was derived from `NX-2021-L/enceladus` (main branch) and `NX-2021-L/enceladus-showcase` (main branch), plus the brand document "ENCELADUS Brand Identity & Visual System v1.0" by J. Reese, April 2026.
