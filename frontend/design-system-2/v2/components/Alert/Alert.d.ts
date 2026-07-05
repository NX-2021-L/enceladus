import * as React from 'react';

export interface AlertProps {
  type?: 'info' | 'success' | 'warning' | 'error';
  header?: React.ReactNode;
  dismissible?: boolean;
  onDismiss?: () => void;
  /** Action slot, typically a Button */
  action?: React.ReactNode;
  children?: React.ReactNode;
}

/** Cloudscape Alert → Enceladus: alpha-tinted panel, 3px status left rule, status dot instead of icon. */
export declare function Alert(props: AlertProps): React.ReactElement | null;
