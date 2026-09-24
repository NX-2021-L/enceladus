import * as React from 'react';

export interface GridColumnDef {
  colspan?: number;
  offset?: number;
}

export interface GridProps {
  /** One entry per child; colspan/offset on a 12-column grid */
  gridDefinition: GridColumnDef[];
  children?: React.ReactNode;
}

/** Cloudscape Grid → Enceladus: 12-column grid with per-child colspan + offset. */
export declare function Grid(props: GridProps): React.ReactElement;
