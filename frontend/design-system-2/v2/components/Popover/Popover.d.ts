import * as React from 'react';

export interface PopoverProps {
  header?: React.ReactNode;
  content?: React.ReactNode;
  triggerType?: 'text' | 'custom';
  dismissButton?: boolean;
  children?: React.ReactNode;
}

/** Cloudscape Popover → Enceladus: surface panel with arrow, dashed teal text trigger, orbital fade-in. */
export declare function Popover(props: PopoverProps): React.ReactElement;
