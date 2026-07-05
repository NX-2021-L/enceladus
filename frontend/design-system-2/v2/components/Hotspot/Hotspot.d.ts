import * as React from 'react';

export interface HotspotProps {
  title?: React.ReactNode;
  content?: React.ReactNode;
  /** Mono step counter, e.g. "Step 2 of 5" */
  stepText?: string;
  side?: 'top' | 'bottom' | 'left' | 'right';
  defaultOpen?: boolean;
}

/** Cloudscape Hotspot → Enceladus: pulsing teal annotation dot + surface popover for onboarding tours. */
export declare function Hotspot(props: HotspotProps): React.ReactElement;
