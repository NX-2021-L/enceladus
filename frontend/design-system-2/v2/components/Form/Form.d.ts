import * as React from 'react';

export interface FormProps {
  header?: React.ReactNode;
  description?: React.ReactNode;
  /** Renders a v2 Alert (type error) above the actions */
  errorText?: React.ReactNode;
  /** Right-aligned action buttons */
  actions?: React.ReactNode;
  children?: React.ReactNode;
}

/** Cloudscape Form → Enceladus: titled section, stacked FormFields, teal-divider action bar. */
export declare function Form(props: FormProps): React.ReactElement;
