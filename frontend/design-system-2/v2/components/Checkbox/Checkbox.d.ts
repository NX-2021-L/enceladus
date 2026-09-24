import * as React from 'react';

export interface CheckboxProps {
  checked?: boolean;
  indeterminate?: boolean;
  disabled?: boolean;
  description?: React.ReactNode;
  onChange?: (event: { detail: { checked: boolean } }) => void;
  children?: React.ReactNode;
}

/** Cloudscape Checkbox → Enceladus: teal fill, void check glyph, 3px radius. */
export declare function Checkbox(props: CheckboxProps): React.ReactElement;
