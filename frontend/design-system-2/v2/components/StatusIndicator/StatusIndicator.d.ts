import * as React from 'react';

export interface StatusIndicatorProps {
  /** Cloudscape status types. success maps to teal (never green) per brand. */
  type?: 'success' | 'error' | 'warning' | 'info' | 'pending' | 'in-progress' | 'loading' | 'stopped';
  children?: React.ReactNode;
}

/** Cloudscape StatusIndicator → Enceladus: pulsing dot + JetBrains Mono label. Success is teal. */
export declare function StatusIndicator(props: StatusIndicatorProps): React.ReactElement;
