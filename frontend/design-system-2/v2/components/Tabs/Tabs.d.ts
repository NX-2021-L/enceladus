import * as React from 'react';

export interface TabItem {
  id: string;
  label: React.ReactNode;
  content?: React.ReactNode;
  /** Mono count beside the label */
  count?: number | string;
  disabled?: boolean;
}

export interface TabsProps {
  tabs: TabItem[];
  activeTabId?: string;
  onChange?: (event: { detail: { activeTabId: string } }) => void;
}

/** Cloudscape Tabs → Enceladus: Space Grotesk labels, teal underline on active, mono counts. */
export declare function Tabs(props: TabsProps): React.ReactElement;
