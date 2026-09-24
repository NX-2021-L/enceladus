import * as React from 'react';

export interface SelectOption {
  value: string;
  label: React.ReactNode;
  description?: React.ReactNode;
  /** Mono tag shown at the right of the option row */
  tag?: string;
}

export interface SelectProps {
  selectedOption?: SelectOption | null;
  options: SelectOption[];
  placeholder?: string;
  disabled?: boolean;
  onChange?: (event: { detail: { selectedOption: SelectOption } }) => void;
}

/** Cloudscape Select → Enceladus: dark trigger, teal focus ring, mono check + tags. */
export declare function Select(props: SelectProps): React.ReactElement;
