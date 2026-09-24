import * as React from 'react';

export interface AttributeItem { key?: string; value?: string; }

export interface AttributeEditorProps {
  items: AttributeItem[];
  addButtonText?: string;
  removeButtonText?: string;
  keyLabel?: string;
  valueLabel?: string;
  onAddButtonClick?: () => void;
  onRemoveButtonClick?: (event: { detail: { itemIndex: number } }) => void;
  onChange?: (event: { detail: { items: AttributeItem[] } }) => void;
}

/** Cloudscape AttributeEditor → Enceladus: mono key/value rows for typed relationship edges. */
export declare function AttributeEditor(props: AttributeEditorProps): React.ReactElement;
