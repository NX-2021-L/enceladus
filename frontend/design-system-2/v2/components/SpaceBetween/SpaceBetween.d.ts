import * as React from 'react';

export interface SpaceBetweenProps {
  direction?: 'vertical' | 'horizontal';
  /** Maps to the Enceladus 4px spacing scale */
  size?: 'xxxs' | 'xxs' | 'xs' | 's' | 'm' | 'l' | 'xl' | 'xxl';
  alignItems?: 'center' | 'start' | 'end' | 'baseline' | 'stretch';
  children?: React.ReactNode;
}

/** Cloudscape SpaceBetween → flex + gap on the Enceladus 4px scale. */
export declare function SpaceBetween(props: SpaceBetweenProps): React.ReactElement;
