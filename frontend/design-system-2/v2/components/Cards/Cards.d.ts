import * as React from 'react';

export interface CardSection<T = any> {
  id?: string;
  header?: React.ReactNode;
  content: (item: T) => React.ReactNode;
}

export interface CardDefinition<T = any> {
  header?: (item: T) => React.ReactNode;
  sections?: CardSection<T>[];
}

export interface CardsProps<T = any> {
  items: T[];
  cardDefinition: CardDefinition<T>;
  header?: React.ReactNode;
  columns?: number;
  selectionType?: 'single' | 'multi';
  selectedItems?: T[];
  trackBy?: string;
  onSelectionChange?: (event: { detail: { selectedItems: T[] } }) => void;
}

/** Cloudscape Cards → Enceladus: surface cards, teal selected border + checkbox, label/value sections. */
export declare function Cards<T = any>(props: CardsProps<T>): React.ReactElement;
