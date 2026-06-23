# A governance incident, retrospected

On 27 February 2026, sessions across Enceladus started failing in a confusing way. Writes were rejected as working from a stale understanding of the rules (`GOVERNANCE_STALE`), and some sessions could not read the governance documents at all. Nothing was obviously broken — connectivity was fine, the services were up — yet the system had quietly lost agreement with itself. This is the short story of what went wrong, because it says something about why the platform is built the way it is.

## The unit of consistency had two origins

Enceladus uses a [governance hash](governance-as-architecture.md) as its unit of consistency: every read returns the hash of the current governance state, and every write must present the hash it was reasoning against. If the two disagree, the write is rejected and the actor re-reads. The whole mechanism depends on one thing being true — that the hash means the same thing everywhere.

It had stopped being true. Two parts of the system were computing the hash from two different sources. One path resolved governance from its canonical home in object storage; another had grown its own separate, local notion of the current state. Most of the time the two agreed and nobody noticed. When they drifted apart, the result was a system that flagged *itself* as stale — the consistency check firing not because an actor was behind, but because the checkers disagreed about reality.

## The lesson

The fix was unremarkable: unify the source, so the hash is computed from one place and the other path falls back to it rather than competing with it. The lesson is the interesting part, and it generalizes well beyond this incident.

When a value's entire job is to *detect divergence*, that value must itself have exactly one origin. Give it two, and you have not built a consistency check — you have built a consistency *bug* that lies dormant until the two origins disagree, and then misattributes its own confusion to everyone downstream. A guardrail with a split source of truth is worse than no guardrail, because it spends its credibility telling you the wrong thing with confidence.

There is a tidy irony here. The platform's central claim is that [governance can be the architecture](governance-as-architecture.md) — that machine-enforced rules are what keep many actors coherent. This incident was that claim being tested in production: a single small breach of the "one source of truth" principle, in the one place the principle matters most, and the immediate, legible cost of it. The system recovered by re-applying its own thesis to itself. That is the most reassuring way for a guardrail to fail — loudly, traceably, and in a direction that teaches you to trust the principle more, not less.
