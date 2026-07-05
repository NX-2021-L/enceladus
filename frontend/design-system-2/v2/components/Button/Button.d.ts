import * as React from 'react';

export interface ButtonProps {
  /** Cloudscape variants; 'danger' added for governance destructive actions */
  variant?: 'primary' | 'normal' | 'link' | 'icon' | 'danger';
  disabled?: boolean;
  /** Shows orbital spinner and disables interaction */
  loading?: boolean;
  /** Render as anchor */
  href?: string;
  onClick?: (event: unknown) => void;
  /** Telemetry decoration — mono record ID suffix, e.g. "ENC-TSK-A57" */
  recordId?: string;
  ariaLabel?: string;
  children?: React.ReactNode;
}

/** Cloudscape Button → Enceladus: Space Grotesk 500, 6px radius, teal fills/outlines, orbital easing. */
export declare function Button(props: ButtonProps): React.ReactElement;
