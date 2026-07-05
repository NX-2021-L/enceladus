import * as React from 'react';

export interface TableColumnDefinition<T = any> {
  id: string;
  header: React.ReactNode;
  cell: (item: T) => React.ReactNode;
  /** Field name enabling click-to-sort on this column */
  sortingField?: string;
}

export interface TableProps<T = any> {
  columnDefinitions: TableColumnDefinition<T>[];
  items: T[];
  header?: React.ReactNode;
  footer?: React.ReactNode;
  selectionType?: 'single' | 'multi';
  selectedItems?: T[];
  /** Key used to identify rows (default "id") */
  trackBy?: string;
  sortingColumn?: { sortingField: string };
  sortingDescending?: boolean;
  empty?: React.ReactNode;
  onSelectionChange?: (event: { detail: { selectedItems: T[] } }) => void;
  onSortingChange?: (event: { detail: { sortingColumn: { sortingField: string }; isDescending: boolean } }) => void;
}

/** Cloudscape Table → Enceladus: surface-alt header row, teal selection, mono cells, sortable columns. */
export declare function Table<T = any>(props: TableProps<T>): React.ReactElement;
