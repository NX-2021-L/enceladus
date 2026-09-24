import * as React from 'react';

export interface KeyValuePair {
  label: React.ReactNode;
  value: React.ReactNode;
  /** Render the value in JetBrains Mono teal (IDs, scores, hashes) */
  mono?: boolean;
}

export interface KeyValuePairsProps {
  items: KeyValuePair[];
  columns?: number;
}

/** Cloudscape KeyValuePairs → Enceladus: uppercase dust keys, optional mono teal values. */
export declare function KeyValuePairs(props: KeyValuePairsProps): React.ReactElement;
