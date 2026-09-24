import * as React from 'react';

export interface PromptInputProps {
  value?: string;
  placeholder?: string;
  disabled?: boolean;
  onChange?: (event: { detail: { value: string } }) => void;
  /** Fired on send button or Enter (Shift+Enter = newline) */
  onAction?: (event: { detail: { value: string } }) => void;
}

/** Cloudscape PromptInput → Enceladus: auto-grow textarea + teal send, for the agent console. */
export declare function PromptInput(props: PromptInputProps): React.ReactElement;
