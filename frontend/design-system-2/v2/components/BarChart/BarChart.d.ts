import * as React from 'react';

export interface ChartSeries {
  title: React.ReactNode;
  /** One value per xDomain entry */
  data: number[];
  color?: string;
}

export interface BarChartProps {
  series: ChartSeries[];
  /** Category labels along the x-axis */
  xDomain: React.ReactNode[];
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  height?: number;
  horizontal?: boolean;
  stacked?: boolean;
}

/** Cloudscape BarChart → Enceladus: inline SVG, teal-family bars, mono axes, orbital grow-in. */
export declare function BarChart(props: BarChartProps): React.ReactElement;
