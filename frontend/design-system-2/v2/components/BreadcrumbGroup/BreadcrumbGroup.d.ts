import * as React from 'react';

export interface BreadcrumbItem {
  text: React.ReactNode;
  href?: string;
}

export interface BreadcrumbGroupProps {
  items: BreadcrumbItem[];
  onFollow?: (event: { detail: { item: BreadcrumbItem; href?: string } }) => void;
}

/** Cloudscape BreadcrumbGroup → Enceladus: teal-light links, slate slash separators, mono for record IDs. */
export declare function BreadcrumbGroup(props: BreadcrumbGroupProps): React.ReactElement;
