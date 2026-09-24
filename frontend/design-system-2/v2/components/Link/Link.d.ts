import * as React from 'react';

export interface LinkProps {
  href?: string;
  /** 'record' renders JetBrains Mono record-ID style (telemetry as decoration) */
  variant?: 'primary' | 'secondary' | 'record';
  /** Appends ↗ and opens in new tab */
  external?: boolean;
  onFollow?: (event: unknown) => void;
  children?: React.ReactNode;
}

/** Cloudscape Link → Enceladus: teal-light with alpha underline; 'record' variant for inline IDs. */
export declare function Link(props: LinkProps): React.ReactElement;
