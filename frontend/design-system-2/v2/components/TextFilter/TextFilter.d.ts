import * as React from 'react';

export interface TextFilterProps {
  filteringText?: string;
  placeholder?: string;
  /** Mono match count, e.g. "3 matches" */
  countText?: React.ReactNode;
  onChange?: (event: { detail: { filteringText: string } }) => void;
}

/** Cloudscape TextFilter → Enceladus: v2 search Input + mono match count. */
export declare function TextFilter(props: TextFilterProps): React.ReactElement;
