import * as React from 'react';

export interface MixedChartBars {
  title: React.ReactNode;
  data: number[];
  color?: string;
}

export interface MixedChartLine {
  title: React.ReactNode;
  data: number[];
  color?: string;
}

export interface MixedChartProps {
  bars?: MixedChartBars;
  line?: MixedChartLine;
  xDomain: React.ReactNode[];
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  height?: number;
  barColor?: string;
  lineColor?: string;
}

/** Cloudscape MixedChart → Enceladus: teal bars with an overlaid amber line, mono axes, orbital draw-in. */
export declare function MixedChart(props: MixedChartProps): React.ReactElement;
