import * as React from 'react';

export interface HelpPanelLink { text: React.ReactNode; href?: string; }

export interface HelpPanelProps {
  header?: React.ReactNode;
  footer?: React.ReactNode;
  /** "Learn more" external links */
  links?: HelpPanelLink[];
  children?: React.ReactNode;
}

/** Cloudscape HelpPanel → Enceladus: surface side panel, teal eyebrow headings, external link list. */
export declare function HelpPanel(props: HelpPanelProps): React.ReactElement;
