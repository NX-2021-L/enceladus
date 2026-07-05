import * as React from 'react';

export interface SideNavItem {
  type?: 'link' | 'section' | 'divider';
  text?: React.ReactNode;
  href?: string;
  /** Mono count at the right of a link */
  count?: number | string;
}

export interface SideNavigationHeader {
  text: React.ReactNode;
  href?: string;
  /** Optional logo image URL rendered before the brand text */
  iconSrc?: string;
}

export interface SideNavigationProps {
  header?: SideNavigationHeader;
  items: SideNavItem[];
  activeHref?: string;
  onFollow?: (event: { detail: { href?: string; text?: React.ReactNode } }) => void;
}

/** Cloudscape SideNavigation → Enceladus: surface rail, teal active bar + tint, mono counts, section labels. */
export declare function SideNavigation(props: SideNavigationProps): React.ReactElement;
