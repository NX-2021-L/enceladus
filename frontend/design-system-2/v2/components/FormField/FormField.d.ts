import * as React from 'react';

export interface FormFieldProps {
  label?: React.ReactNode;
  /** Small "info" link/hint after the label */
  info?: React.ReactNode;
  description?: React.ReactNode;
  errorText?: React.ReactNode;
  /** Mono constraint hint under the control */
  constraintText?: React.ReactNode;
  children?: React.ReactNode;
}

/** Cloudscape FormField → Enceladus: seafoam label, dust description, crimson dot error, mono constraint. */
export declare function FormField(props: FormFieldProps): React.ReactElement;
