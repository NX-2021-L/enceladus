import * as React from 'react';

export interface BoxProps {
  /** Text role; 'mono' renders teal tabular numerals, 'code' an inline code chip */
  variant?: 'p' | 'small' | 'strong' | 'label' | 'code' | 'mono' | 'awsui';
  /** Cloudscape color token or any CSS color */
  color?: string;
  textAlign?: 'left' | 'center' | 'right';
  margin?: string;
  padding?: string;
  display?: string;
  children?: React.ReactNode;
}

/** Cloudscape Box → Enceladus typographic utility mapped onto the brand type system. */
export declare function Box(props: BoxProps): React.ReactElement;
