import * as React from 'react';

export interface DatePickerProps {
  /** YYYY/MM/DD */
  value?: string;
  placeholder?: string;
  onChange?: (event: { detail: { value: string } }) => void;
}

/** Cloudscape DatePicker → Enceladus: mono trigger + teal calendar popover, ISO-ish YYYY/MM/DD. */
export declare function DatePicker(props: DatePickerProps): React.ReactElement;
