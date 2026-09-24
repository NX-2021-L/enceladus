import * as React from 'react';

export interface SpinnerProps {
  size?: 'small' | 'normal' | 'big' | 'large';
}

/** Cloudscape Spinner → Enceladus: teal orbital ring, linear rotation (orbital motion, no spring). */
export declare function Spinner(props: SpinnerProps): React.ReactElement;
