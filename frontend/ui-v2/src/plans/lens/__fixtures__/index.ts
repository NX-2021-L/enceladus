/** The eleven golden fixtures of DOC-F3E7C341EB27 section 7, in order. Ten are live plans read on 2026-11-19; F11 is synthetic. */
import type { GoldenFixture } from './builders'
import { F1 } from './F01-trk-pln-001'
import { F2 } from './F02-hfy-pln-004'
import { F3 } from './F03-enc-pln-102'
import { F4 } from './F04-enc-pln-106'
import { F5 } from './F05-dvp-pln-013'
import { F6 } from './F06-enc-pln-107'
import { F7 } from './F07-fin-pln-009'
import { F8 } from './F08-fin-pln-010'
import { F9 } from './F09-int-pln-033'
import { F10 } from './F10-int-pln-031'
import { F11 } from './F11-synthetic-label-precedence'

export const GOLDEN_FIXTURES: readonly GoldenFixture[] = [F1, F2, F3, F4, F5, F6, F7, F8, F9, F10, F11]
export { F1, F2, F3, F4, F5, F6, F7, F8, F9, F10, F11 }
export type { GoldenFixture, ExpectedWave, FixtureRow } from './builders'
export { task, kids, feature } from './builders'
