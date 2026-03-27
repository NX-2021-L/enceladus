SELECT *
FROM hive.devops_agentcli_db.features t
WHERE t.ingest_ts = (
  SELECT MAX(t2.ingest_ts)
  FROM hive.devops_agentcli_db.features t2
  WHERE t2.project = t.project
)