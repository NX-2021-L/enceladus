import * as React from 'react';

export interface WizardStep {
  title: React.ReactNode;
  content?: React.ReactNode;
}

export interface WizardProps {
  steps: WizardStep[];
  activeStepIndex?: number;
  onNavigate?: (event: { detail: { requestedStepIndex: number } }) => void;
  onCancel?: () => void;
  onSubmit?: () => void;
}

/** Cloudscape Wizard → Enceladus: numbered rail with teal done/active markers, primary Next/Submit. */
export declare function Wizard(props: WizardProps): React.ReactElement;
