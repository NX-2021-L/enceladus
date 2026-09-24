import * as React from 'react';

export interface ColumnLayoutProps {
  columns?: number;
  /** 'vertical' inserts teal-divider rules between columns */
  borders?: 'none' | 'vertical';
  children?: React.ReactNode;
}

/** Cloudscape ColumnLayout → Enceladus: equal-width grid, optional teal dividers. */
export declare function ColumnLayout(props: ColumnLayoutProps): React.ReactElement;
