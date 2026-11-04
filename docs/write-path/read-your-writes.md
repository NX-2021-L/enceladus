# Read-your-writes on the Enceladus write path

Every governed write (tracker and document) is acknowledged as soon as DynamoDB commits it. The response carries `t_ack` (epoch ms), `version_seq` (the committed value) and `server_total_ms`. That commit is the only synchronous truth. Everything else, the graph, the feed, the search index and the compliance score, is a projection that follows asynchronously from the DynamoDB stream.

## What a client should do

- Read DynamoDB (`tracker.get`, `documents.get`) for truth immediately after a write. Those reads see the committed item, including `version_seq`, `t_ack` and `projection_status`.
- Treat graph, feed and search results as eventually consistent. They converge within `governed_lag_ms`, measured from `t_ack` to the end of the projection and published in the `Enceladus/WritePath` metrics.
- Never poll a projection to decide whether a write succeeded. A write succeeded when the response said so.

## Knowing when a projection has caught up

Each item carries `projection_status` and `projected_version_seq`. A write sets `projection_status` to `pending`. After graph_sync projects that exact `version_seq` it sets `projection_status` to `projected` and `projected_version_seq` to the same number, using a conditional update that only moves the value forward. A client that needs the projection (for example a graph query that must include its own write) re-reads the item and waits until `projected_version_seq >= version_seq` from the write response, with a bounded timeout.

`feed_published_version_seq` plays the same role for the feed publisher.

## Delivery guarantees

Consumers are idempotent on `version_seq`. Duplicate or out-of-order deliveries result in one projection at the highest `version_seq`. Consumer-originated updates to `projection_status`, `projected_version_seq`, `t_projected` and `feed_published_version_seq` are skipped by every stream consumer, so they never cause a feedback loop. Records that exhaust their retries land in an on-failure queue, and `IteratorAge` and queue-depth alarms fire on lag or failures.
