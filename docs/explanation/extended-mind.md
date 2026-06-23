# The extended mind

In 1998 Andy Clark and David Chalmers asked a deceptively simple question: where does the mind stop and the rest of the world begin? Their answer — the *extended mind* thesis — was that when a piece of the environment is reliably available, trusted, and woven into how an agent reasons, it is not merely an aid to cognition but a genuine *part* of it. Their parable was Otto, a man with memory loss who keeps a notebook. Otto's notebook does for him what biological memory does for everyone else; the only difference is that it sits outside his skull. If we would call the belief "in memory" for someone with intact recall, intellectual honesty demands we call it a belief for Otto too. The notebook is part of his mind.

Enceladus takes this seriously as an engineering principle. The agents that work in it are large language models, and a language model has, by construction, the memory problem Otto has: nothing it learns in one session survives into the next. Its working memory is a context window — lossy, ephemeral, and expensive — that is wiped clean every time the conversation resets. This document explains the design response: give the agents an Otto's notebook, and make it good enough to count.

## Why a context window is not a mind

The naive way to give an agent memory is to stuff more into its context: paste in the history, the related tickets, the prior decisions, and hope the relevant fact survives the summarization. This fails in two directions at once. It is too much — context is finite and the important detail drowns in the merely recent. And it is too little — anything that happened before this conversation, or in a sibling agent's conversation, simply is not there.

The deeper problem is that a context window is *re-derived* every session from whatever happened to be assembled. It is not a stable external structure the agent can return to and trust. Otto's notebook works precisely because it is none of those things: it is durable, it is the same notebook tomorrow, and Otto does not re-justify each entry before relying on it. A memory you must reconstruct and re-verify every morning is not yet a memory.

## What Enceladus externalizes, and why it is ontological

The platform's answer is to move the agents' working memory *out* of the context window and into a governed, shared record — and, crucially, to make that record **ontological** rather than a pile of text.

The work-state is not stored as documents to be re-read. It is stored as typed records — tasks, issues, features, plans, lessons — connected by typed edges: a task is `CHILD_OF` a feature, a fix `BLOCKS` a release, an issue `DUPLICATES` another, a design `RELATES_TO` a decision, a worklog `MENTIONS` a record by name. This typing is what makes the memory queryable in ways a vector blob never could be. "What is blocking this?" "What did we learn the last time we touched this subsystem?" "What plan does this task serve?" are graph questions, and the ontology is built to answer them directly.

That choice — typed structure over undifferentiated text — is the difference between a memory you can *search* and a memory you can *reason over*. Vector similarity will find you things that sound alike. The ontology finds you things that are actually related, because the relationship was named when it was created.

## Lessons: the memory that learns

The clearest expression of the extended-mind idea in Enceladus is the **lesson** primitive. When an agent discovers something durable — a non-obvious failure mode, a recipe that works, a fact about the system that cost effort to learn — it can write a lesson into the shared record. Future agents, in unrelated sessions, retrieve it when it is relevant and cite it in their reasoning.

Lessons are not retained uniformly. Their salience decays and reinforces on a spaced-repetition schedule (an FSRS-style stability model), so that a lesson confirmed again and again rises in confidence and surfaces readily, while one that was never corroborated quietly falls below the threshold at which it is offered. The system is not just remembering; it is *consolidating* — strengthening what keeps proving true and letting the rest fade. That is a recognizably mnemonic behavior, implemented in a database.

## Meeting the parity criteria

Clark and Chalmers proposed criteria for when external structure earns the status of mind: it must be **reliably available**, **readily accessible**, **automatically endorsed** (trusted without re-deriving it each time), and a **past product of conscious endorsement** (it got there deliberately). The governed substrate is designed to meet exactly these.

It is available because it is durable and append-only — the record is there next session, and the session after that. It is accessible because [hybrid retrieval](v4-graph-and-hybrid-retrieval.md) brings the relevant slice to the agent on demand rather than making it hunt. It is trusted because governance guarantees the provenance: every entry is attributed, validated, and lifecycle-gated, so an agent can rely on a record without re-litigating it — the same way Otto does not re-verify his notebook. And it is a product of deliberate endorsement because nothing enters the record except through a governed, intentional write.

The retrieval and the consolidation are the moving parts; the [governance](governance-as-architecture.md) is what makes them *trustworthy enough to count*. An external memory you cannot trust is just more noise. A governed one can be treated as part of the mind.

## The boundary that dissolves

The interesting consequence is that the line between "the agent" and "the system" stops being sharp. An agent in Enceladus is not a model with a prompt; it is a model *plus* the slice of the governed record it can reach, reason over, and extend. Two agents in different sessions, drawing on the same lessons and the same graph, are in a real sense sharing a mind — not by passing messages, but by reading and writing the same external memory.

That is the wager: that the path to capable, *coherent* multi-agent engineering runs less through bigger context windows and more through a better notebook — one that is typed, governed, queryable, and shared.
