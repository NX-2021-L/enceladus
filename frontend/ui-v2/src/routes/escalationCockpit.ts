/**
 * DVP-TSK-A20: the data and decide path of the restored escalations cockpit. ONE all-projects
 * source (project_id=*): no per-project fan-out and no ESC-only reader (DVP-TSK-981 AC1). Every
 * verdict goes through the kit: If-Match (the card etag) + subject version, an Idempotency-Key,
 * the callHash for approvals that run a call, and a step-up proof for high/critical or
 * requiredAuth step_up cards. The backend remains the arbiter of the human-only gates.
 */
import {
  assertVerdictAllowed, callHashFor, createGateSource, GateHttpError, makeIdempotencyKey, needsStepUp,
  type DecideInput, type DecideProof, type DecideReceipt, type GateCard, type State, type Verdict,
} from '@io-kit/gates'
import type { StepUpProviderLike } from '@io-kit/gates/react'
import { gateFetch, humanSession, stepUpProvider } from './GateInboxPanel'

export const gateSource = createGateSource({ baseUrl: '', fetch: gateFetch, getHumanSession: humanSession })

const PENDING: State[] = ['pending', 'snoozed']
const TERMINAL: State[] = ['decided', 'expired', 'superseded']
const TERMINAL_CAP = 100

export interface CockpitFeed {
  cards: GateCard[]
  terminalError: string | null
}

export async function fetchCockpitFeed(compact = false): Promise<CockpitFeed> {
  const pending = gateSource.list({ projects: 'all', state: PENDING })
  let terminalError: string | null = null
  const terminal = compact
    ? Promise.resolve<GateCard[]>([])
    : gateSource.list({ projects: 'all', state: TERMINAL, pageSize: TERMINAL_CAP }).catch((e: unknown) => {
        terminalError = e instanceof Error ? e.message : String(e)
        return [] as GateCard[]
      })
  const [p, t] = await Promise.all([pending, terminal])
  return { cards: [...p, ...t.slice(0, TERMINAL_CAP * 3)].map(normalizeCard), terminalError }
}

function arrayField<T>(value: unknown): T[] | undefined {
  let v = value
  if (typeof v === 'string') {
    try { v = JSON.parse(v) } catch { return undefined }
  }
  return Array.isArray(v) ? (v as T[]) : undefined
}

/**
 * DVP-TSK-B30: the hub stores producer and recipe gate fields as JSON strings. A card served with
 * one unparsed (proposedCalls before B30) crashed EscalationDetail (`calls.map`) and made the kit
 * hash the legacy triple instead of the call, so read string arrays back and drop non-arrays.
 */
export function normalizeCard(card: GateCard): GateCard {
  return {
    ...card,
    proposedCalls: arrayField<NonNullable<GateCard['proposedCalls']>[number]>(card.proposedCalls),
    candidates: arrayField<NonNullable<GateCard['candidates']>[number]>(card.candidates),
    evidence: arrayField<GateCard['evidence'][number]>(card.evidence) ?? [],
  }
}

export const cardNeedsStepUp = (card: GateCard): boolean =>
  needsStepUp(card) || card.risk === 'high' || card.risk === 'critical'

export async function decideCard(
  card: GateCard,
  verdict: Verdict,
  stepUp: StepUpProviderLike = stepUpProvider,
): Promise<DecideReceipt> {
  if (card.id === undefined || card.project_id === undefined || card.etag === undefined) {
    throw new Error('This card carries no etag yet, so it cannot be decided from here.')
  }
  assertVerdictAllowed(card, verdict)
  let proof: DecideProof | undefined
  if (cardNeedsStepUp(card) && (verdict.type === 'approve' || verdict.type === 'deny')) {
    proof = (await stepUp.stepUp()) as unknown as DecideProof
  }
  const input: DecideInput = {
    id: card.id, project: card.project_id, etag: card.etag, subjectVersion: card.subject.version,
    verdict, idempotencyKey: makeIdempotencyKey(card.id, verdict.type),
  }
  if (proof !== undefined) input.proof = proof
  if (verdict.type === 'approve' && (verdict.candidateId !== undefined || (card.proposedCalls?.length ?? 0) > 0)) {
    input.callHash = await callHashFor(card, verdict.candidateId)
  }
  return gateSource.decide(input)
}

export interface CockpitNotice {
  type: 'success' | 'warning' | 'error'
  header: string
  detail: string
  receipt?: string
}

export function describeReceipt(card: GateCard, verdict: Verdict, receipt: DecideReceipt): CockpitNotice {
  const dec = (receipt.decision ?? {}) as Record<string, unknown>
  const ref = [dec.hash, receipt.hash, receipt.receipt_id, receipt.id].find((v) => typeof v === 'string') as string | undefined
  return {
    type: 'success',
    header: `${verdict.type} recorded for ${card.id}`,
    detail: `${card.project_id} / ${card.kind}: the verdict is recorded as a receipt bound to the card version.`,
    receipt: JSON.stringify(ref ? { receipt: ref, ...(receipt.success !== undefined ? { success: receipt.success } : {}) } : receipt).slice(0, 600),
  }
}

// DVP-TSK-984 (E41-R3): the hub's 403 step-up refusals. Cognito reports no amr, so the rule is a fresh
// managed-login sign-in (auth_time within 5 minutes), where the passkey is the offered factor.
const STEP_UP_REFUSALS = new Set(['step_up_required', 'step_up_rejected', 'step_up_unverified', 'auth_context_incomplete'])

export function describeError(e: unknown, cardChanged: boolean): CockpitNotice {
  const message = e instanceof Error ? e.message : String(e)
  if (/redirect/i.test(`${(e as { name?: string })?.name ?? ''} ${message}`)) {
    return { type: 'warning', header: 'Continuing sign-in', detail: 'Continuing sign-in to confirm your identity; choose again when you return.' }
  }
  if (e instanceof GateHttpError && e.status === 403 && e.reason !== undefined && STEP_UP_REFUSALS.has(e.reason)) {
    return {
      type: 'warning', header: 'Sign in with your passkey',
      detail: 'This decision needs a fresh sign-in from the last 5 minutes. Sign in with your passkey, then choose again.',
    }
  }
  if (cardChanged) {
    return { type: 'warning', header: 'Card changed', detail: 'This card changed since it was rendered (412); the queue was refreshed. Review it and choose again.' }
  }
  return { type: 'error', header: 'Decision was not recorded', detail: message }
}
