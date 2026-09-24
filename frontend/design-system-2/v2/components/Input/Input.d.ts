import * as React from 'react';

export interface InputChangeDetail { value: string; }

export interface InputProps {
  value?: string;
  placeholder?: string;
  type?: 'text' | 'password' | 'search' | 'number' | 'email' | 'url';
  disabled?: boolean;
  invalid?: boolean;
  /** Render the field value in JetBrains Mono (IDs, hashes, hex) */
  mono?: boolean;
  /** Leading icon node */
  icon?: React.ReactNode;
  onChange?: (event: { detail: InputChangeDetail }) => void;
  ariaLabel?: string;
}

/** Cloudscape Input → Enceladus: #0D1220 field, teal focus ring, optional mono value. */
export declare function Input(props: InputProps): React.ReactElement;
