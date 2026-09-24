import * as React from 'react';

export interface CopyToClipboardProps {
  textToCopy: string;
  /** Shown instead of the raw text (inline variant) */
  displayText?: React.ReactNode;
  variant?: 'inline' | 'button';
}

/** Cloudscape CopyToClipboard → Enceladus: mono value + copy button, teal check confirmation. */
export declare function CopyToClipboard(props: CopyToClipboardProps): React.ReactElement;
