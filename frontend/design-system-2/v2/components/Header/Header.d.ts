import * as React from 'react';

export interface HeaderProps {
  variant?: 'h1' | 'h2' | 'h3';
  /** Mono counter, e.g. "(17)" */
  counter?: string;
  /** Telemetry decoration — mono teal record ID beside the title */
  recordId?: string;
  description?: React.ReactNode;
  /** Right-aligned actions slot, typically Buttons */
  actions?: React.ReactNode;
  children?: React.ReactNode;
}

/** Cloudscape Header → Enceladus: Space Grotesk seafoam title, mono counter + record-ID inline. */
export declare function Header(props: HeaderProps): React.ReactElement;
