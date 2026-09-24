import * as React from 'react';

export interface UploadedFile { name: string; size: number; }

export interface FileUploadProps {
  value?: UploadedFile[];
  multiple?: boolean;
  constraintText?: React.ReactNode;
  accept?: string;
  onChange?: (event: { detail: { value: UploadedFile[] } }) => void;
}

/** Cloudscape FileUpload → Enceladus: dashed teal dropzone, mono file sizes, crimson remove. */
export declare function FileUpload(props: FileUploadProps): React.ReactElement;
