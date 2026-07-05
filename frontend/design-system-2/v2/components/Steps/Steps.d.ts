import * as React from 'react';

export interface StepItem {
  header: React.ReactNode;
  details?: React.ReactNode;
  status?: 'success' | 'error' | 'loading' | 'pending';
}

export interface StepsProps {
  steps: StepItem[];
}

/** Cloudscape Steps → Enceladus: vertical rail, teal completed markers, mono detail lines. Ideal for evidence-gated lifecycles. */
export declare function Steps(props: StepsProps): React.ReactElement;
