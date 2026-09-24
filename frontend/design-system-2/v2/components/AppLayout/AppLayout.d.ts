import * as React from 'react';

export interface AppLayoutProps {
  /** v2 TopNavigation */
  topNavigation?: React.ReactNode;
  /** v2 SideNavigation */
  navigation?: React.ReactNode;
  navigationOpen?: boolean;
  /** v2 BreadcrumbGroup */
  breadcrumbs?: React.ReactNode;
  content?: React.ReactNode;
  /** v2 HelpPanel or Drawer (right rail) */
  tools?: React.ReactNode;
  toolsOpen?: boolean;
  /** v2 SplitPanel (bottom inspector) */
  splitPanel?: React.ReactNode;
}

/** Cloudscape AppLayout → Enceladus: the cockpit shell — top nav, collapsible side nav, breadcrumbs, content, tools rail, split panel. */
export declare function AppLayout(props: AppLayoutProps): React.ReactElement;
