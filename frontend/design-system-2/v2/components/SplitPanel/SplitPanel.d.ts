import * as React from 'react';

export interface SplitPanelProps {
  header?: React.ReactNode;
  defaultOpen?: boolean;
  /** Controlled open state */
  open?: boolean;
  onToggle?: (event: { detail: { open: boolean } }) => void;
  children?: React.ReactNode;
}

/** Cloudscape SplitPanel → Enceladus: bottom drawer with grip handle + teal chevron, detail inspector. */
export declare function SplitPanel(props: SplitPanelProps): React.ReactElement;
