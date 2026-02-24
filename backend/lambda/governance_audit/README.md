# Enceladus Governance Audit Lambda

`enceladus-governance-audit` consumes DynamoDB Streams events from
`devops-project-tracker` and publishes SNS alerts when writes are missing
or carry invalid `write_source` attribution.

Related work:
- `ENC-ISS-009`
- `ENC-TSK-454`

## Known Write Channels

- `mcp_server`
- `tracker_cli`
- `mutation_api`
- `feed_publisher`

Any `INSERT` or `MODIFY` event with:
- missing `write_source`
- empty `write_source.channel`
- unknown `write_source.channel`

is treated as a governance anomaly and pushed to
`arn:aws:sns:us-west-2:356364570033:devops-project-json-sync`.

## Deploy

From this directory:

```bash
./deploy.sh
```

The script packages `lambda_function.py`, updates the Lambda code in `us-west-2`,
waits for the update to complete, and prints final function metadata.

## Validate

Quick config checks:

```bash
aws lambda get-function-configuration \
  --function-name enceladus-governance-audit \
  --region us-west-2

aws lambda list-event-source-mappings \
  --function-name enceladus-governance-audit \
  --region us-west-2
```

Runtime smoke test:

```bash
python3 -m pytest -q test_lambda_function.py
```
