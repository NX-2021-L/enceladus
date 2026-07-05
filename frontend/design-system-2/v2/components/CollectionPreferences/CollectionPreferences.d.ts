import * as React from 'react';

export interface PageSizeOption { value: number; label: React.ReactNode; }
export interface ColumnOption { id: string; label: React.ReactNode; }

export interface CollectionPreferencesProps {
  title?: string;
  pageSizeOptions?: PageSizeOption[];
  pageSize?: number;
  visibleColumns?: string[];
  columnOptions?: ColumnOption[];
  onConfirm?: (event: { detail: { pageSize?: number; visibleColumns: string[] } }) => void;
}

/** Cloudscape CollectionPreferences → Enceladus: gear trigger + popover with RadioGroup page size + Checkbox columns. */
export declare function CollectionPreferences(props: CollectionPreferencesProps): React.ReactElement;
