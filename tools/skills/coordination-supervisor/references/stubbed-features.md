# Stubbed Features

Features reserved for future iteration. Each is defined in the coordination supervisor design document but not yet implemented in the skill.

Source: DOC-D4D7D8606824

---

## F1: Concurrency Map

**Description**: Render a live map of the four-silo workspace state, showing which agent sessions are active, what tasks they hold checkouts on, and which worktrees are in use.

**Design reference**: DOC-D4D7D8606824 section F1

**Status**: Stubbed for future iteration

---

## F4: Executive Summary Engine

**Description**: Generate 3-5 paragraph summaries of plan gate status, aggregating progress across active features, blocked tasks, and pending deploy requests into a concise briefing for io.

**Design reference**: DOC-D4D7D8606824 section F4

**Status**: Stubbed for future iteration

---

## F5: Velocity Telemetry Reader

**Description**: Scan changelog entries, task worklogs, and deploy history for anomalies within a specified time window. Surface throughput drops, unusually long checkout durations, or deploy failure clusters.

**Design reference**: DOC-D4D7D8606824 section F5

**Status**: Stubbed for future iteration

---

## F7: Decision Surfacing Queue

**Description**: Maintain an explicit queue of items requiring io's judgment. Items enter the queue from F6 rejections (failed HANDOFF verification), ambiguous dispatch targets, and cross-feature dependency conflicts that cannot be resolved algorithmically.

**Design reference**: DOC-D4D7D8606824 section F7

**Status**: Stubbed for future iteration

---

## F8: Anchor-Word Resonance Check

**Description**: Alignment test against io's anchor-word set: convergence, will, flow, play, surrender, force, balance, love, resonance, telemetry. Used to validate that dispatch plans and summaries maintain tonal coherence with the project's design philosophy.

**Design reference**: DOC-D4D7D8606824 section F8

**Status**: Stubbed for future iteration

---

## F9: Substrate Resilience and Fallback Pivot

**Description**: Clean degradation when the MCP surface fails. Define fallback behaviors for each supervisor feature when DynamoDB, S3, or the governance hash endpoint is unavailable. Includes circuit-breaker thresholds and io-notification triggers.

**Design reference**: DOC-D4D7D8606824 section F9

**Status**: Stubbed for future iteration
