import * as React from 'react';

export interface PropertyFilterToken {
  propertyKey: string;
  operator: string;
  value: string;
}

export interface PropertyFilterQuery {
  tokens: PropertyFilterToken[];
  operation?: 'and' | 'or';
}

export interface FilteringProperty {
  key: string;
  operators?: string[];
}

export interface PropertyFilterProps {
  query?: PropertyFilterQuery;
  filteringProperties?: FilteringProperty[];
  placeholder?: string;
  hint?: React.ReactNode;
  onChange?: (event: { detail: PropertyFilterQuery }) => void;
}

/** Cloudscape PropertyFilter → Enceladus: mono token chips (key op value), type `field:value` + Enter to add. */
export declare function PropertyFilter(props: PropertyFilterProps): React.ReactElement;
