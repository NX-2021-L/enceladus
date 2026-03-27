
WITH latest AS (
  SELECT *
  FROM hive.devops_agentcli_db.issues t
  WHERE t.ingest_ts = (
    SELECT MAX(t2.ingest_ts)
    FROM hive.devops_agentcli_db.issues t2
    WHERE t2.project = t.project
  )
),
enriched AS (
  SELECT
    t.*,
    element_at(
      CAST(coalesce(try(json_parse(t.history)), json_parse('[]'))
        AS ARRAY(ROW(description VARCHAR, status VARCHAR, timestamp VARCHAR))),
      -1
    ) AS last_entry
  FROM latest t
)
SELECT
  description,
  history,
  hypothesis,
  id,
  priority,
  related,
  severity,
  status,
  title,
  debug_log,
  impacts,
  acceptance_criteria,
  symptoms,
  technical_notes,
  project,
  ingest_ts,
  coalesce(
    try(from_iso8601_timestamp(last_entry.timestamp)),
    try(CAST(last_entry.timestamp AS timestamp with time zone))
  ) AS parse_last_update,
  last_entry.description AS parse_last_update_note
FROM enriched;
