import * as React from 'react';

export interface TopNavIdentity {
  title?: React.ReactNode;
  href?: string;
  /** Optional logo image URL; falls back to the inline orbital-mark SVG */
  iconSrc?: string;
}

export interface TopNavUtility {
  type?: 'button' | 'badge' | 'avatar';
  text?: React.ReactNode;
  /** Mono badge on a button */
  badge?: React.ReactNode;
  /** Avatar initials */
  initials?: string;
  onClick?: () => void;
}

export interface TopNavigationProps {
  identity?: TopNavIdentity;
  utilities?: TopNavUtility[];
}

/** Cloudscape TopNavigation → Enceladus: blurred void bar, orbital-mark wordmark, mono utility badges. */
export declare function TopNavigation(props: TopNavigationProps): React.ReactElement;
