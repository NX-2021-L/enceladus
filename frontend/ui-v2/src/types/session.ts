/**
 * Agent-session record shape (ENC-FTR-117 / ENC-TSK-I37, minted server-side by
 * coordination_api agent.register -> agent.claim). This is a DISTINCT
 * governance primitive from the six tracker/document RecordType shapes in
 * ./records.ts — sessions are NOT project-scoped (session_id is globally
 * unique) and are NOT read through the tracker_mutation /{project}/{type}/{id}
 * endpoint, so they deliberately live outside RecordShapeMap/RecordType.
 *
 * ENC-TSK-L35 (B67 PWA2.0 session detail + worklog mirroring) adds `history`:
 * whenever this session appends a worklog entry to ANY tracker record, a
 * mirrored copy of that entry is also appended here server-side
 * (tracker_mutation._mirror_worklog_to_session), so the session's own detail
 * page can show a worklog-style activity feed across every record it touched.
 */

export interface SessionWorklogEntry {
  timestamp: string
  status: string
  description: string
  /** Present on ENC-TSK-L35 mirrored entries; absent on pre-L35 rows. */
  source_record_type?: string
  source_record_id?: string
}

export interface Session {
  session_id: string
  agent_type_id: string
  parent_session_id: string
  runtime: string
  status: 'allocated' | 'claimed' | 'retired'
  created_at: string
  claimed_at: string
  /** Bumped on every session-requiring call (ENC-TSK-L35); absent on very old rows. */
  updated_at?: string
  /** J83/L35 heartbeat — refreshed alongside updated_at. */
  last_activity_at?: string
  sci_token_id?: string
  credential_id?: string
  /** Mirrored worklog entries (ENC-TSK-L35). Absent (not empty) on sessions
   * that predate the mirroring feature and have never had one mirrored. */
  history?: SessionWorklogEntry[]
}
