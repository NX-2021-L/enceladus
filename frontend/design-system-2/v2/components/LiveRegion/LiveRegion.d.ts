import * as React from 'react';

export interface LiveRegionProps {
  /** Use assertive for errors; polite (default) for status */
  assertive?: boolean;
  /** Render visibly (mono) instead of screen-reader-only */
  visible?: boolean;
  children?: React.ReactNode;
}

/** Cloudscape LiveRegion → Enceladus: aria-live announcer, visually-hidden by default, mono when visible. */
export declare function LiveRegion(props: LiveRegionProps): React.ReactElement;
