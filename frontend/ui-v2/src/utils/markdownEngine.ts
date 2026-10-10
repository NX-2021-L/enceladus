/**
 * markdownEngine.ts -- DVP-TSK-916 (DVP-PLN-011 E3-W2.3): which renderer the
 * document views use.
 *
 * `legacy` (default this release) is the hand-rolled parser in
 * components/MarkdownContent.tsx plus the manifest-sliced section view.
 * `kit` renders the document through @io-kit/md's docstore preset
 * (components/KitDocumentView.tsx). The flag is OFF by default for one
 * release; flipping the default and removing the legacy parser is DVP-TSK-924
 * (E3-W3.4), so `legacy` must stay selectable until then.
 *
 * Resolution order: `?md=kit` / `?md=legacy` query flag, then the per-user
 * preference in localStorage (`ev2.md.engine`), then `legacy`.
 */
export type MarkdownEngine = 'kit' | 'legacy'

export const MARKDOWN_ENGINE_QUERY_PARAM = 'md'
export const MARKDOWN_ENGINE_STORAGE_KEY = 'ev2.md.engine'

/** The release default. DVP-TSK-924 flips this to 'kit' and deletes the legacy path. */
export const DEFAULT_MARKDOWN_ENGINE: MarkdownEngine = 'legacy'

function parseEngine(value: string | null | undefined): MarkdownEngine | null {
  const v = value?.trim().toLowerCase()
  return v === 'kit' || v === 'legacy' ? v : null
}

function readPreference(): string | null {
  try {
    return window.localStorage.getItem(MARKDOWN_ENGINE_STORAGE_KEY)
  } catch {
    return null
  }
}

export function resolveMarkdownEngine(
  search: string = typeof window === 'undefined' ? '' : window.location.search,
  preference: string | null = typeof window === 'undefined' ? null : readPreference(),
): MarkdownEngine {
  const fromQuery = parseEngine(new URLSearchParams(search).get(MARKDOWN_ENGINE_QUERY_PARAM))
  return fromQuery ?? parseEngine(preference) ?? DEFAULT_MARKDOWN_ENGINE
}

/** Persist (or clear, with null) the per-user preference. Never throws. */
export function setMarkdownEnginePreference(engine: MarkdownEngine | null): void {
  try {
    if (engine) window.localStorage.setItem(MARKDOWN_ENGINE_STORAGE_KEY, engine)
    else window.localStorage.removeItem(MARKDOWN_ENGINE_STORAGE_KEY)
  } catch {
    /* storage unavailable: the query flag still works */
  }
}
