import * as React from 'react';

export interface AreaSeries {
  title: React.ReactNode;
  data: number[];
  color?: string;
}

export interface AreaChartProps {
  series: AreaSeries[];
  xDomain: React.ReactNode[];
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  height?: number;
  stacked?: boolean;
}

/** Cloudscape AreaChart → Enceladus: inline SVG, teal-family gradient fills, mono axes. */
export declare function AreaChart(props: AreaChartProps): React.ReactElement;
