import * as React from 'react';

export interface RadioItem {
  value: string;
  label: React.ReactNode;
  description?: React.ReactNode;
  disabled?: boolean;
}

export interface RadioGroupProps {
  value?: string;
  items: RadioItem[];
  name?: string;
  onChange?: (event: { detail: { value: string } }) => void;
}

/** Cloudscape RadioGroup → Enceladus: teal ring + fill, dust descriptions. */
export declare function RadioGroup(props: RadioGroupProps): React.ReactElement;
