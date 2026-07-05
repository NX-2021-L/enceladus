import * as React from 'react';

export interface DrawerProps {
  header?: React.ReactNode;
  /** Mono record ID beside the title */
  recordId?: string;
  onClose?: () => void;
  children?: React.ReactNode;
}

/** Cloudscape Drawer → Enceladus: right-edge surface panel, mono record-ID header, scrollable body. */
export declare function Drawer(props: DrawerProps): React.ReactElement;
