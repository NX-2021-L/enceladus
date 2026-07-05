import * as React from 'react';

export interface PieDatum {
  title: React.ReactNode;
  value: number;
  color?: string;
}

export interface PieChartProps {
  data: PieDatum[];
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  variant?: 'pie' | 'donut';
  size?: number;
  /** Overrides the donut center readout (defaults to total) */
  centerLabel?: React.ReactNode;
}

/** Cloudscape PieChart → Enceladus: inline SVG donut/pie, teal-family palette, mono center + percentages. */
export declare function PieChart(props: PieChartProps): React.ReactElement;
