import * as React from 'react';

export interface ToggleButtonProps {
  pressed?: boolean;
  disabled?: boolean;
  iconOn?: React.ReactNode;
  iconOff?: React.ReactNode;
  onChange?: (event: { detail: { pressed: boolean } }) => void;
  children?: React.ReactNode;
}

/** Cloudscape ToggleButton → Enceladus: field surface, teal-tint pressed state. */
export declare function ToggleButton(props: ToggleButtonProps): React.ReactElement;
