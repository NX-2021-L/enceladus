import * as React from 'react';

export interface TileItem {
  value: string;
  label: React.ReactNode;
  description?: React.ReactNode;
  disabled?: boolean;
}

export interface TilesProps {
  value?: string;
  items: TileItem[];
  columns?: number;
  name?: string;
  onChange?: (event: { detail: { value: string } }) => void;
}

/** Cloudscape Tiles → Enceladus: selectable surface cards, teal selected border + radio dot. */
export declare function Tiles(props: TilesProps): React.ReactElement;
