import * as React from 'react';

export interface ToggleProps {
  checked?: boolean;
  disabled?: boolean;
  onChange?: (event: { detail: { checked: boolean } }) => void;
  children?: React.ReactNode;
}

/** Cloudscape Toggle → Enceladus: slate→teal track, orbital knob slide. */
export declare function Toggle(props: ToggleProps): React.ReactElement;
