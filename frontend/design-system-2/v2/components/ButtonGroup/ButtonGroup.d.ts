import * as React from 'react';

export interface ButtonGroupItem {
  id?: string;
  text?: string;
  icon?: React.ReactNode;
  disabled?: boolean;
  /** Mono confirmation tooltip flashed after click (e.g. "Copied") */
  popoverFeedback?: string;
  type?: 'button' | 'separator';
}

export interface ButtonGroupProps {
  items: ButtonGroupItem[];
  onItemClick?: (event: { detail: { id?: string } }) => void;
}

/** Cloudscape ButtonGroup → Enceladus: segmented icon action strip with mono feedback tooltip. */
export declare function ButtonGroup(props: ButtonGroupProps): React.ReactElement;
