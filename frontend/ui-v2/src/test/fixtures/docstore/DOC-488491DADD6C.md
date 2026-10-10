# DOC-488491DADD6C W-C3 Reconcile: md (DVP-TSK-821)

**Project**: devops
**Related**: DVP-TSK-821, DVP-PLN-007, DVP-FTR-098, DOC-AEF68227FEBB, DOC-85B6774DAC96, DOC-90930433E582, DOC-7789FF132F90, DOC-C97D5B581CB4, DOC-5132058DFFAB
**Author**: DVP-TSK-821 subagent of ENC-SES-0IT (claude sonnet)
**Created**: 2026-10-10

## 0. Scope and inputs

Scope: reconcile the md (markdown rendering) design area across the four audited stacks into one decision and one canonical `@io-kit/md` API, as W-C3 of DVP-PLN-007 under DVP-FTR-098. Tags: `[DOC]` is traceable to a pack input, `[INF]` is inference.

```yaml
inputs:
  - {id: DOC-AEF68227FEBB, role: "Wave A audit cell, enceladus.jreese.net md"}
  - {id: DOC-85B6774DAC96, role: "Wave A audit cell, ai.vagamod.io md"}
  - {id: DOC-90930433E582, role: "Wave A audit cell, think.thepup.io md"}
  - {id: DOC-7789FF132F90, role: "Wave A audit cell, coach.thepup.io md"}
  - {id: DOC-C97D5B581CB4, role: "Wave B research W-B3 (DVP-TSK-813), state of the art and candidate API"}
  - {id: DOC-5132058DFFAB, role: "Matrix cell field definition (s4), referenced not re-read"}
not_available:
  - "Source code of any stack; only the audit cells and W-B3 text were read"
  - "Measured parse latency, bundle size or real corpus timings for any stack"
  - "Whether think's react-markdown output is separately sanitized (DOC-90930433E582 says not verified)"
  - "Vagamod comment rendering (DOC-85B6774DAC96 says not read)"
```

## 1. Area-by-stack matrix

```yaml
enceladus:
  present: partial   # [DOC] DOC-AEF68227FEBB
  implementation: "Hand-rolled block+inline parser in frontend/ui-v2/src/components/MarkdownContent.tsx; DocumentSection.tsx, utils/documentSections.ts, primitives/DocumentPrimitive.tsx"
  patterns: [ENC-/DOC- id auto-linking to routes, long-token wrapping, section outline, section editor with conflict view]
  quality_signals:
    tests: "3 files: MarkdownContent, DocumentSection, DocumentSectionsView"   # [DOC]
    sanitization: "React escaping only, no dangerouslySetInnerHTML"            # [DOC]
    gaps: "No tables (explicit in file header), no syntax highlighting, no link scheme filter, no YAML or metadata renderer"  # [DOC]/[INF] per audit notes
    latency: "synchronous, no parse cache [INF]"
  source: DOC-AEF68227FEBB
vagamod:
  present: "no"      # [DOC] DOC-85B6774DAC96
  implementation: "none; comments posted to /objects/{id}/comments, probably plain text [INF]"
  patterns: []
  quality_signals: {tests: none, open_iss: none-found}
  source: DOC-85B6774DAC96
think:
  present: "yes"     # [DOC] DOC-90930433E582
  implementation: "react-markdown ^10.1.0 + react-syntax-highlighter + dompurify; design-system MarkdownRenderer.jsx, CodeBlock.jsx; pwa renderers/MarkdownRenderer.jsx, lib/sanitizeHtml.js, detail/registry.ts"
  patterns: [renderer_hint typed renderer registry, presigned-URL body fetch with one 403 retry, DOMPurify allow-list on archived HTML, styled GFM tables]
  quality_signals:
    tests: "verify-xss-sanitization.mjs (22 lines), verify-presign-retry.mjs (89 lines)"   # [DOC]
    docstore_awareness: "none; generic CommonMark/GFM"                                      # [DOC]
    gaps: "No size cap or lazy render [INF]; react-markdown output sanitization unverified"
  source: DOC-90930433E582
coach:
  present: "no"      # [DOC] DOC-7789FF132F90
  implementation: "none; notes are plain text plus emoji"
  patterns: []
  quality_signals: {tests: none, open_iss: none-found}
  source: DOC-7789FF132F90
```

## 2. Best-of-breed

Decision: a merge, with think as the engine and enceladus as the semantics. Neither stack wins alone. [INF] (supported by DOC-C97D5B581CB4 s1 reading: "the two halves of a good renderer already exist, but in different stacks").

```yaml
winner_engine:
  stack: think
  adopt:
    - "react-markdown on unified/remark/rehype, a hast-to-React pipeline with no HTML-string sink [DOC DOC-C97D5B581CB4 s2.1]"
    - "renderer_hint typed registry as the top-level dispatch; markdown becomes one renderer [DOC DOC-90930433E582, DOC-C97D5B581CB4 s4]"
    - "presigned-URL fetch with one 403 retry [DOC DOC-90930433E582]"
    - "GFM tables"
  retire:
    - "react-syntax-highlighter, replaced by Shiki 4 fine-grained [DOC DOC-C97D5B581CB4 s2.3]"
    - "DOMPurify as the primary markdown sanitizer; replaced by rehype-sanitize. Keep pinned >=3.4.7 only for non-markdown archived HTML until removed [DOC DOC-C97D5B581CB4 s2.2, s3]"
winner_semantics:
  stack: enceladus
  adopt:
    - "ENC-/DOC- id auto-linking, ported as an idLinks plugin using find-and-replace (DVP- added) [DOC DOC-AEF68227FEBB; DOC-C97D5B581CB4 s2.4]"
    - "long-token wrapping, ported as CSS overflow-wrap:anywhere"
    - "section outline and section editor with conflict view; the editor stays in enceladus but is fed by the kit's parseOutline/replaceSection"
  retire:
    - "the hand-rolled parser, after golden-corpus parity"
other_contributions:
  vagamod: "Greenfield consumer; proves the RSC adapter (KitMarkdownServer) and Tailwind token mapping. Contributes no code. [INF]"
  coach: "Greenfield JS consumer; proves the core profile (no mermaid, no YAML tree) and a per-note format flag for plain-text notes. [INF]"
rationale:
  - "Section addressing, ID linking and outline require an AST; the hand-rolled parser has one only implicitly, whereas remark gives mdast. [INF]"
  - "The hand-rolled parser lacks tables and highlighting and is maintained by one stack; replacing it is cheaper than extending it. [INF]"
  - "Risk is regression in section addressing; mitigated by golden tests on a real 15-80 KB docstore corpus. [DOC DOC-C97D5B581CB4 s3]"
```

## 3. Canonical kit API

Package: `@io-kit/md`, a framework-free core with a React adapter at `@io-kit/md/react`. It follows DOC-C97D5B581CB4 s5 for all signatures. Departures are listed at the end of this section.

```ts
// Core, framework-free
export interface MdDocument {
  source: string; mdast: Root; meta: DocMeta | null;
  outline: OutlineNode[]; sections: Section[];
  claims: { doc: number; inf: number };
}
export interface DocMeta { id?: string; title: string; project?: string; related: RecordRef[];
  author?: string; created?: string; extra: Record<string, string> }
export interface OutlineNode { depth: 1|2|3|4|5|6; text: string; slug: string; headingPath: string[];
  blockIds: string[]; position: { start: number; end: number }; children: OutlineNode[] }
export interface Section { headingPath: string[]; slug: string; hash: string; position: { start: number; end: number } }
export interface RecordRef { id: string; kind: 'ENC'|'DOC'|'DVP'|string; href?: string; label?: string }
export type IdResolver = (id: string) => { href: string; title?: string; status?: string } | null;

export interface SanitizePolicy {
  version: 1;
  rawHtml: 'escape' | 'drop';                    // never 'allow'
  schema: 'github' | Schema;
  protocols: { href: string[]; src: string[] };  // defaults ['http','https','mailto'] / ['https']
  internalSchemes: string[];
  clobberPrefix: string;                         // 'user-content-'
  externalLinks: { rel: string; target?: '_blank' };
}
export const defaultPolicy: SanitizePolicy;

export interface MdPlugin { name: string; remark?: PluggableList; rehype?: PluggableList;
  components?: Partial<Record<string, ComponentType<any>>>;
  lazy?: () => Promise<Partial<MdPlugin>>; sanitizeAllow?: Partial<Schema> }

export function parse(source: string, opts?: { plugins?: MdPlugin[] }): MdDocument;
export function parseOutline(source: string): OutlineNode[];
export function sectionAt(doc: MdDocument, anchor: string): Section | null;
export function replaceSection(source: string, headingPath: string[], next: string, baseHash: string):
  { ok: true; source: string } | { ok: false; conflict: { theirs: string; base: string } };

// Presets
export function docstore(opts?: { resolver?: IdResolver; metaCard?: boolean; claimBadges?: boolean; yamlView?: 'tree'|'code' }): MdPlugin[];
export function idLinks(resolver: IdResolver, pattern?: RegExp): MdPlugin;
export function code(opts?: { langs: string[]; themes: [light: string, dark: string]; worker?: boolean }): MdPlugin;
export function mermaid(opts?: { sandbox: 'iframe' }): MdPlugin;

// Registry (new, from think)
export type RendererHint = 'markdown' | 'plaintext' | string;
export interface RendererRegistry { register(hint: RendererHint, r: ComponentType<RendererProps>): void; resolve(hint: RendererHint): ComponentType<RendererProps> }
export function createRegistry(defaults?: Partial<Record<RendererHint, ComponentType<RendererProps>>>): RendererRegistry;

// React adapter (@io-kit/md/react)
export function KitMarkdown(props: { source: string | MdDocument; plugins?: MdPlugin[]; policy?: SanitizePolicy;
  sectioned?: boolean; onAnchor?: (a: string) => void; components?: Partial<Record<string, ComponentType<any>>> }): JSX.Element;
export async function KitMarkdownServer(props: Parameters<typeof KitMarkdown>[0]): Promise<JSX.Element>;
export function useOutline(doc: MdDocument): { active: string; outline: OutlineNode[] };
```

### 3.1 Docstore-convention plugin set (the docstore() preset)

```yaml
plugins:
  metadata_header:
    input: "consecutive **Project**/**Related**/**Author**/**Created** lines after the H1 '# <ID> Title'"
    behavior: "lifted into DocMeta; rendered as a header card (definition list); Related ids become chips with resolver status; unknown **Key** lines go to meta.extra; remark-frontmatter parsed too for imported docs"
  yaml_blocks:
    input: "fenced yaml"
    behavior: "parse with yaml (1.2); collapsible tree with copy-as-source; on parse error show highlighted source plus a non-blocking warning; default-on under 200 lines (W-B3 OD-4)"
  id_links:
    input: "ENC-/DOC-/DVP- ids in text, not inside code or existing links"
    behavior: "mdast find-and-replace to link nodes via IdResolver; unresolved ids render as plain monospace, never broken links"
  claim_badges:
    input: "[DOC] and [INF], including in YAML comments"
    behavior: "accessible badges ('documented claim', 'inference'); per-document tally in header card; [INF] links to the inference register anchor when present"
  section_anchors:
    behavior: "github-slugger slugs (de-duplicated); #<slug> for headings; #s/<heading-path-slugs>/b<n> for blocks; hashchange scroll; heading self-link copies the full record URL; sanitize ordering per sanitization policy"
  pipe_tables:
    behavior: "render as GFM; authoring views emit a lint hint pointing at ENC-LSN-026"
  long_tokens:
    behavior: "overflow-wrap:anywhere on inline code and ids (ported from enceladus)"
```

### 3.2 Sanitization policy

```yaml
sanitization_policy:
  pipeline: "remark -> rehype with raw HTML disabled (no rehype-raw) -> docstore plugins -> rehype-sanitize LAST -> hast-to-React. No API returns an HTML string to a browser sink."   # [DOC DOC-C97D5B581CB4 s2.2, s5]
  raw_html: "escaped as text (default) or dropped; never allowed for agent content"
  schema: "rehype-sanitize defaultSchema (GitHub), with docstore classes and data-* attributes explicitly allowed through plugin sanitizeAllow deltas"
  url_protocols: {href: [http, https, mailto], src: [https], internal: "enc: scheme resolved by IdResolver"}
  dom_clobbering: "ids prefixed user-content-; kit slug prefix allow-listed, or slug after sanitize"
  external_links: "rel noopener noreferrer"
  dompurify: "not used in the md path; pinned >=3.4.7 only as fallback for non-markdown HTML (archived capture, mermaid SVG)"
  trusted_types: "kit ships policy name and helper; each stack sets its own CSP header, report-only first (W-B3 OD-5)"
  ci_audit: "every plugin sanitizeAllow delta is snapshot-tested"
```

### 3.3 Where this follows and departs from DOC-C97D5B581CB4

```yaml
follows:
  - "All of s5 signatures: MdDocument, DocMeta, OutlineNode, SanitizePolicy, MdPlugin, parse, parseOutline, sectionAt, replaceSection, docstore, idLinks, code, mermaid, KitMarkdown, KitMarkdownServer, useOutline"
  - "s6 docstore rendering rules as the section 3.1 plugin set"
  - "s2.2 sanitization stack (rehype-sanitize, Trusted Types, DOMPurify on hold)"
departs:
  - change: "Adds Section type, which W-B3 references but does not define"
    why: "MdDocument.sections and sectionAt need a concrete shape. [INF]"
  - change: "Adds RendererRegistry/createRegistry to the kit"
    why: "W-B3 s4 stage 1 says adopt think's renderer_hint registry as top-level dispatch but s5 has no API for it. [INF]"
  - change: "Pins this wave's decision to a merge: think engine, enceladus semantics"
    why: "W-B3 leaves the winner implicit; DVP-TSK-821 requires it to be explicit. [INF]"
  - change: "Mermaid and Trusted Types enforcement stay behind flags; YAML tree default-on only under 200 lines"
    why: "Open decisions OD-3/4/5 are still io's; this takes the W-B3 recommendations as defaults only. [INF]"
```

## 4. Migration order

```yaml
order:
  - {rank: 1, stack: kit, risk: low, effort: M, prerequisite: "io decisions OD-1 (registry) and OD-2 (block ids); extract core from think's react-markdown pipeline; golden corpus of real 15-80 KB docstore docs"}
  - {rank: 2, stack: think, risk: low, effort: S, prerequisite: "kit 1.0 published; contract tests green; markdown hint switched to @io-kit/md, DOMPurify kept >=3.4.7 for archived HTML only, react-syntax-highlighter removed"}
  - {rank: 3, stack: coach, risk: low, effort: S, prerequisite: "kit core profile; per-note format flag so existing plain-text notes are not reinterpreted; JS consumer typings verified"}
  - {rank: 4, stack: vagamod, risk: medium, effort: M, prerequisite: "kit RSC adapter; bundle budget in CI to stop Shiki reaching the client; Tailwind 3 vs 4 token mapping"}
  - {rank: 5, stack: enceladus, risk: high, effort: M, prerequisite: "docstore preset passes all section-addressing and id-link golden tests; section editor re-pointed at parseOutline/replaceSection; old parser kept behind a flag for one release"}
rationale: "Lowest risk first. Enceladus is last because it holds the only production section editor and the only docstore semantics; it migrates once the kit has proven the engine on think and the greenfield stacks. [INF]"
```

## 5. Consumer contract tests

Tests live inside the kit and run per consumer. [DOC brief]

```yaml
- {id: MD-CT-01, asserts: "CommonMark and GFM corpus renders identically to snapshot, including tables, task lists and fenced code", applies_to: [enceladus, vagamod, think, coach]}
- {id: MD-CT-02, asserts: "Raw HTML, script, iframe, on* handlers, javascript:/data: URLs and srcdoc never reach the DOM; XSS fixture corpus (superset of think's verify-xss-sanitization) passes", applies_to: [enceladus, vagamod, think, coach]}
- {id: MD-CT-03, asserts: "No HTML-string sink: no dangerouslySetInnerHTML or innerHTML in kit output; Trusted Types report-only emits zero violations", applies_to: [enceladus, vagamod, think, coach]}
- {id: MD-CT-04, asserts: "Heading slugs are GitHub-compatible and de-duplicated; headingPath and #s/<path>/b<n> anchors resolve and scroll on hashchange, with the user-content- prefix handled", applies_to: [enceladus, vagamod, think]}
- {id: MD-CT-05, asserts: "ENC-/DOC-/DVP- ids link via resolver outside code and links; unresolved ids render monospace, not broken links", applies_to: [enceladus, vagamod, think]}
- {id: MD-CT-06, asserts: "Metadata header card parses Project/Related/Author/Created, Related chips resolve, extra keys preserved; unparsable header falls back to plain body", applies_to: [enceladus, think]}
- {id: MD-CT-07, asserts: "YAML fences render as tree, fall back to source on parse error, and [DOC]/[INF] badges and the per-document tally match a counted fixture", applies_to: [enceladus, think]}
- {id: MD-CT-08, asserts: "replaceSection by heading path with base hash: success path round-trips source; hash mismatch returns conflict {theirs, base} consumed by the existing conflict view; non-structural edits keep block ids", applies_to: [enceladus]}
- {id: MD-CT-09, asserts: "Long tokens (80+ chars ids, URLs in inline code) do not cause horizontal overflow at 375 px", applies_to: [enceladus, vagamod, think, coach]}
- {id: MD-CT-10, asserts: "An 80 KB docstore document renders within the parse budget (initial target 50 ms on target iPhone, tunable) and sectioned mode re-renders only changed sections", applies_to: [enceladus, vagamod, think]}
- {id: MD-CT-11, asserts: "RSC build: KitMarkdownServer output hydrates and no Shiki code enters the client bundle", applies_to: [vagamod]}
- {id: MD-CT-12, asserts: "Core profile (no mermaid, no YAML tree) renders notes behind the per-note format flag; plain-text notes are untouched when the flag is off", applies_to: [coach]}
- {id: MD-CT-13, asserts: "Registry dispatch: markdown hint resolves to KitMarkdown, unknown hints resolve to content-unavailable, presigned 403 retries once", applies_to: [think]}
- {id: MD-CT-14, asserts: "sanitizeAllow deltas for every plugin match their committed snapshot", applies_to: [enceladus, vagamod, think, coach]}
```

## 6. Open decisions for io

```yaml
- {id: OD-1, question: "Registry and naming for @io-kit/md (CodeArtifact vs npm private)", recommendation: "CodeArtifact (W-B3 OD-1) [DOC DOC-C97D5B581CB4]"}
- {id: OD-2, question: "Block-id scheme, positional b<n> vs persisted ids in source comments", recommendation: "Positional now (W-B3 OD-2) [DOC DOC-C97D5B581CB4]"}
- {id: OD-3, question: "Mermaid in stage 2 or 3", recommendation: "Stage 2 behind flag, enceladus only (W-B3 OD-3) [DOC DOC-C97D5B581CB4]"}
- {id: OD-4, question: "YAML tree default-on or opt-in", recommendation: "Default-on under 200 lines (W-B3 OD-4) [DOC DOC-C97D5B581CB4]"}
- {id: OD-5, question: "Trusted Types enforcement owner", recommendation: "Kit ships helper, stacks set headers (W-B3 OD-5) [DOC DOC-C97D5B581CB4]"}
- {id: OD-6, question: "Confirm the merge decision (think engine, enceladus semantics) over extending the hand-rolled parser", recommendation: "Confirm the merge; the extend option leaves a one-stack parser with no tables or highlighting [INF]"}
- {id: OD-7, question: "Does vagamod render markdown in comments today, and should comments use the core profile", recommendation: "Verify during rank 4 migration; DOC-85B6774DAC96 did not read comment rendering [INF]"}
```

## Inference register

```yaml
- "Section 2 merge decision: think engine plus enceladus semantics beats extending either alone"
- "The hand-rolled parser has only an implicit AST, so section addressing is safer on mdast"
- "Vagamod and coach contribute patterns (RSC adapter, core profile) but no code, since both have no renderer"
- "Section 3 additions: Section type, RendererRegistry/createRegistry, and the choice to take W-B3 OD recommendations as defaults"
- "Section 4 ordering and all risk/effort ratings follow W-B3 s3 ratings, themselves inference"
- "Section 5 test set, the 50 ms budget, and test-to-stack applicability"
- "Section 6 OD-6 and OD-7 recommendations"
- "Gaps flagged: no code was read, so think react-markdown sanitization and vagamod comment rendering remain unverified"
```
