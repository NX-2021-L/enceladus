/**
 * DVP-TSK-A20: the data and decide path of the restored escalations cockpit. ONE all-projects
 * source (project_id=*): no per-project fan-out and no ESC-only reader (DVP-TSK-981 AC1). Every
 * verdict goes through the kit: If-Match (the card etag) + subject version, an Idempotency-Key,
 * the callHash for approvals that run a call, and a step-up proof for high/critical or
 * requiredAuth step_up cards. The backend remains the arbiter of the human-only gates.
 */
import {
  assertVerdictAllowed, callHashFor, createGateSource, GateHttpError, makeIdempotencyKey,
  type DecideInput, type DecideReceipt, type GateCard, type State, type Verdict,
} from '@io-kit/gates'
import { gateFetch, humanSession } from './GateInboxPanel'

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

/**
 * ENC-TSK-R50 AC5: a 412 hands back the re-rendered card (fresh etag and subject version). Swap it
 * into the cached feed so the open modal decides against it at once, before the refetch lands.
 */
export function replaceCard(feed: CockpitFeed | undefined, card: GateCard): CockpitFeed | undefined {
  if (feed === undefined) return feed
  const same = (c: GateCard) => c.id === card.id && c.project_id === card.project_id
  return feed.cards.some(same) ? { ...feed, cards: feed.cards.map((c) => (same(c) ? card : c)) } : feed
}

export async function decideCard(
  card: GateCard,
  verdict: Verdict,
): Promise<DecideReceipt> {
  if (card.id === undefined || card.project_id === undefined || card.etag === undefined) {
    throw new Error('This card carries no etag yet, so it cannot be decided from here.')
  }
  assertVerdictAllowed(card, verdict)
  const input: DecideInput = {
    id: card.id, project: card.project_id, etag: card.etag, subjectVersion: card.subject.version,
    verdict, idempotencyKey: makeIdempotencyKey(card.id, verdict.type),
  }
  // ENC-TSK-R51 / ENC-ISS-865: every approve carries the callHash. A strict (explicit-kind)
  // mutation_type card has no proposedCalls, but the hub still requires one (428 without it);
  // callHashFor hashes the legacy {mutation_type, target_record_id, payload} triple the hub hashes.
  if (verdict.type === 'approve') {
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

// ES-R7: no step-up; a signed-in allow-listed approver decides any risk with the existing session.

/**
 * `fresh` is the re-rendered card a 412 carried (cardFromConflict) and `sent` the card the verdict
 * was posted against. A 412 is recoverable: the cockpit swaps in `fresh`, so the copy says what
 * changed and asks for a second look instead of reporting a failure (ENC-TSK-R50 AC5).
 */
export function describeError(e: unknown, fresh?: GateCard, sent?: GateCard): CockpitNotice {
  const message = e instanceof Error ? e.message : String(e)
  if (/redirect/i.test(`${(e as { name?: string })?.name ?? ''} ${message}`)) {
    return { type: 'warning', header: 'Continuing sign-in', detail: 'Continuing sign-in to confirm your identity; choose again when you return.' }
  }
  if (fresh !== undefined) {
    const reason = e instanceof GateHttpError ? e.reason : undefined
    if (reason === 'subject_changed') {
      const from = sent?.subject.version || '—'
      const to = fresh.subject.version || '—'
      return {
        type: 'warning', header: 'The record changed',
        detail: `The record changed since you opened this card (version ${from} to ${to}). Review the change and approve again.`,
      }
    }
    return {
      type: 'warning', header: 'The escalation changed',
      detail: 'This escalation changed since you opened it, and the card now shows its current state. Review it and choose again.',
    }
  }
  if (e instanceof GateHttpError && e.status === 428) {
    // ENC-TSK-R51 AC5: the hub names the precondition the request lacked; say that, not a generic failure.
    const hub = (e.body as { error?: unknown } | null)?.error
    return {
      type: 'error', header: 'This escalation could not be approved',
      detail: typeof hub === 'string' && hub !== '' ? hub : message,
    }
  }
  return { type: 'error', header: 'Decision was not recorded', detail: message }
}
