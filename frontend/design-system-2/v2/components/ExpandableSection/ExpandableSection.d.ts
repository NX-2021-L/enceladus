import * as React from 'react';

export interface ExpandableSectionProps {
  headerText?: React.ReactNode;
  /** Mono counter at the right of the header */
  headerCounter?: React.ReactNode;
  variant?: 'default' | 'footer';
  defaultExpanded?: boolean;
  /** Controlled expansion */
  expanded?: boolean;
  onChange?: (event: { detail: { expanded: boolean } }) => void;
  children?: React.ReactNode;
}

/** Cloudscape ExpandableSection → Enceladus: teal rotating chevron, Space Grotesk header, mono counter. */
export declare function ExpandableSection(props: ExpandableSectionProps): React.ReactElement;
