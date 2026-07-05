import * as React from 'react';

export interface FlashbarItem {
  id: string;
  type?: 'success' | 'error' | 'warning' | 'info' | 'in-progress';
  header?: React.ReactNode;
  content?: React.ReactNode;
  dismissible?: boolean;
  onDismiss?: () => void;
  /** Shows orbital spinner */
  loading?: boolean;
  /** Telemetry decoration — mono record ID beside the header */
  recordId?: string;
}

export interface FlashbarProps {
  items: FlashbarItem[];
}

/** Cloudscape Flashbar → Enceladus: solid teal/crimson bars for terminal states, bordered surface for info. */
export declare function Flashbar(props: FlashbarProps): React.ReactElement;
