import * as React from 'react';

export interface ContainerProps {
  /** Typically a v2 Header component */
  header?: React.ReactNode;
  footer?: React.ReactNode;
  children?: React.ReactNode;
}

/** Cloudscape Container → Enceladus: #111827 surface, teal-alpha border brightening on hover, no shadow lift. */
export declare function Container(props: ContainerProps): React.ReactElement;
