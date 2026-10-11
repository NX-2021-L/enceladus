import type { IdResolver } from '@io-kit/md/lean'

export interface MarkdownContentProps {
  /** Raw markdown source -- a record description, evidence string, worklog entry, or document body. */
  text?: string | null
  /** Alias for `text` (ENC-TSK-M34 interim call-site compatibility). Prefer `text`. */
  content?: string | null
  /** Owning record's project -- resolves bare ENC-TSK/ISS/FTR/PLN/LSN tokens to a same-project route. */
  projectId?: string
  className?: string
  /**
   * Kit engine only: replaces the legacy id resolution (ENC-TSK/ISS/FTR/PLN/LSN + DOC) with a resolver
   * that also knows the other project prefixes (DVP-, INT-, ...). Document views pass makeKitIdResolver.
   */
  idResolver?: IdResolver
}
