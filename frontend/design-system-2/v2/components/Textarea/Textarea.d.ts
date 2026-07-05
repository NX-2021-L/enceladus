import * as React from 'react';

export interface TextareaProps {
  value?: string;
  placeholder?: string;
  rows?: number;
  disabled?: boolean;
  invalid?: boolean;
  /** Render in JetBrains Mono (JSON, code, hashes) */
  mono?: boolean;
  onChange?: (event: { detail: { value: string } }) => void;
  ariaLabel?: string;
}

/** Cloudscape Textarea → Enceladus: #0D1220 field, teal focus ring, vertical resize. */
export declare function Textarea(props: TextareaProps): React.ReactElement;
