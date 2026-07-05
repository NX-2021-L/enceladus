import * as React from 'react';

export interface MultiselectOption { value: string; label: React.ReactNode; }

export interface MultiselectProps {
  selectedOptions?: MultiselectOption[];
  options: MultiselectOption[];
  placeholder?: string;
  onChange?: (event: { detail: { selectedOptions: MultiselectOption[] } }) => void;
}

/** Cloudscape Multiselect → Enceladus: teal-alpha token chips in trigger, checkbox menu. */
export declare function Multiselect(props: MultiselectProps): React.ReactElement;
