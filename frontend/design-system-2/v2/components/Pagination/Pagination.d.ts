import * as React from 'react';

export interface PaginationProps {
  currentPageIndex?: number;
  pagesCount?: number;
  disabled?: boolean;
  onChange?: (event: { detail: { currentPageIndex: number } }) => void;
}

/** Cloudscape Pagination → Enceladus: mono page numbers, teal active page, chevron arrows. */
export declare function Pagination(props: PaginationProps): React.ReactElement;
