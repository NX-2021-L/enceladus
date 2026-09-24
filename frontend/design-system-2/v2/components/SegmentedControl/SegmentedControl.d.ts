import * as React from 'react';

export interface SegmentOption {
  id: string;
  text: React.ReactNode;
  disabled?: boolean;
}

export interface SegmentedControlProps {
  selectedId?: string;
  options: SegmentOption[];
  onChange?: (event: { detail: { selectedId: string } }) => void;
}

/** Cloudscape SegmentedControl → Enceladus: teal filled active segment, Space Grotesk labels. */
export declare function SegmentedControl(props: SegmentedControlProps): React.ReactElement;
