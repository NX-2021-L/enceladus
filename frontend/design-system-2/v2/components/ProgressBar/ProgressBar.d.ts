import * as React from 'react';

export interface ProgressBarProps {
  /** 0–100 */
  value?: number;
  label?: React.ReactNode;
  description?: React.ReactNode;
  status?: 'in-progress' | 'success' | 'error';
  /** Mono result line shown under the track on completion */
  resultText?: string;
}

/** Cloudscape ProgressBar → Enceladus: slate track, teal fill, mono tabular percentage. */
export declare function ProgressBar(props: ProgressBarProps): React.ReactElement;
