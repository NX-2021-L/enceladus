import * as React from 'react';

export interface LineSeries {
  title: React.ReactNode;
  data: number[];
  color?: string;
}

export interface LineChartProps {
  series: LineSeries[];
  xDomain: React.ReactNode[];
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  height?: number;
  yMax?: number;
}

/** Cloudscape LineChart → Enceladus: inline SVG, teal draw-in path + dots, mono axes. */
export declare function LineChart(props: LineChartProps): React.ReactElement;
