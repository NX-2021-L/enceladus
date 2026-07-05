import * as React from 'react';

export interface ButtonDropdownItem {
  id?: string;
  text?: React.ReactNode;
  description?: React.ReactNode;
  danger?: boolean;
  disabled?: boolean;
  type?: 'item' | 'divider';
}

export interface ButtonDropdownProps {
  items: ButtonDropdownItem[];
  variant?: 'normal' | 'primary';
  disabled?: boolean;
  onItemClick?: (event: { detail: { id?: string } }) => void;
  children?: React.ReactNode;
}

/** Cloudscape ButtonDropdown → Enceladus: teal trigger + chevron, surface menu, danger/mono items. */
export declare function ButtonDropdown(props: ButtonDropdownProps): React.ReactElement;
