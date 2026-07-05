import * as React from 'react';

export interface TokenItem {
  label: React.ReactNode;
  disabled?: boolean;
  /** Render this token's label in JetBrains Mono teal (record IDs) */
  mono?: boolean;
}

export interface TokenGroupProps {
  items: TokenItem[];
  /** Render all labels in mono */
  mono?: boolean;
  onDismiss?: (event: { detail: { itemIndex: number } }) => void;
}

/** Cloudscape TokenGroup → Enceladus: teal-alpha chips, crimson-on-hover dismiss. */
export declare function TokenGroup(props: TokenGroupProps): React.ReactElement;
