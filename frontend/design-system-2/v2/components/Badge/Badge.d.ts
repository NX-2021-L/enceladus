import * as React from 'react';

export interface BadgeProps {
  /** Enceladus palette mapping of Cloudscape's blue/grey/green/red */
  color?: 'teal' | 'teal-light' | 'crimson' | 'lavender' | 'dust' | 'amber';
  children?: React.ReactNode;
}

/** Small mono-type chip. Cloudscape Badge → Enceladus: JetBrains Mono, 4px radius, alpha fills. */
export declare function Badge(props: BadgeProps): React.ReactElement;
