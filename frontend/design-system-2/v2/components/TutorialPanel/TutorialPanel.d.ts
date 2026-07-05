import * as React from 'react';

export interface Tutorial {
  title: React.ReactNode;
  description?: React.ReactNode;
  stepsCount?: number;
  completedSteps?: number;
}

export interface TutorialPanelProps {
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  tutorials: Tutorial[];
  onStart?: (event: { detail: { index: number } }) => void;
}

/** Cloudscape TutorialPanel → Enceladus: surface tutorial cards with teal progress bars + start/continue. */
export declare function TutorialPanel(props: TutorialPanelProps): React.ReactElement;
