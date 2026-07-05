import * as React from 'react';

export interface ContentLayoutProps {
  /** Page header band (surface-alt), typically a v2 Header */
  header?: React.ReactNode;
  children?: React.ReactNode;
}

/** Cloudscape ContentLayout → Enceladus: distinct header band + padded content column. */
export declare function ContentLayout(props: ContentLayoutProps): React.ReactElement;
