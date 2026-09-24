import * as React from 'react';

export interface AutosuggestOption {
  value: string;
  description?: React.ReactNode;
  tag?: string;
}

export interface AutosuggestProps {
  value?: string;
  options: AutosuggestOption[];
  placeholder?: string;
  emptyText?: React.ReactNode;
  onChange?: (event: { detail: { value: string } }) => void;
  ariaLabel?: string;
}

/** Cloudscape Autosuggest → Enceladus: v2 Input + filtered menu with teal match highlight. */
export declare function Autosuggest(props: AutosuggestProps): React.ReactElement;
