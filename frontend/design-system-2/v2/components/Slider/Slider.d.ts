import * as React from 'react';

export interface SliderProps {
  value?: number;
  min?: number;
  max?: number;
  step?: number;
  disabled?: boolean;
  /** Format the mono value readout, e.g. (v) => v.toFixed(2) */
  valueFormatter?: (value: number) => string;
  /** Tick labels rendered under the track */
  ticks?: React.ReactNode[];
  onChange?: (event: { detail: { value: number } }) => void;
  ariaLabel?: string;
}

/** Cloudscape Slider → Enceladus: slate track with teal fill + glow thumb, mono readout. */
export declare function Slider(props: SliderProps): React.ReactElement;
