import * as React from 'react';

export interface ModalProps {
  visible?: boolean;
  header?: React.ReactNode;
  /** Mono record ID beside the title */
  recordId?: string;
  size?: 'small' | 'medium' | 'large';
  footer?: React.ReactNode;
  onDismiss?: () => void;
  children?: React.ReactNode;
}

/** Cloudscape Modal → Enceladus: blurred void overlay, surface dialog, orbital rise, Escape/backdrop close. */
export declare function Modal(props: ModalProps): React.ReactElement | null;
