"""Synthetic multi-hop QA dataset generator (ENC-TSK-I99 / ENC-FTR-104 Ph2 AC-4).

WHY SYNTHETIC (honest-limitations disclosure)
----------------------------------------------
FTR-104 AC-4 asks for RRF-vs-GHN multi-hop recall@k on at least two of
{MuSiQue, 2WikiMultiHopQA, HotpotQA}. The real dataset splits are NOT fetchable
in this build/worktree sandbox:

  * outbound network is blocked (HuggingFace / GitHub raw both fail TLS cert
    verification — verified 2026-07-02 with urllib against huggingface.co);
  * the ``datasets`` library is not installed and cannot be pip-installed
    offline;
  * the raw JSONL splits (MuSiQue ~200MB, 2Wiki/HotpotQA larger) are not present
    anywhere on the image.

So instead of silently faking numbers "as if" they came from the real corpora,
this module *constructs* documented synthetic multi-hop QA samples whose
STRUCTURE mirrors each target dataset's published construction, then the harness
runs the identical RRF and GHN scorers over them. The recall@k deltas therefore
measure a real algorithmic property (does graph-coupled energy descent recover
graph-reachable bridge facts that rank fusion misses?) on a controlled proxy —
they are NOT a claim about absolute recall on the real leaderboards. Any lesson
candidate derived from this must carry that caveat.

Dataset structural profiles (from the papers)
---------------------------------------------
  * HotpotQA (Yang et al. 2018): 2-hop, "bridge" + "comparison" questions;
    relatively high lexical overlap between the question and BOTH supporting
    paragraphs (Wikipedia intro paragraphs), ~8 distractor paragraphs per
    question. -> easiest; RRF should already do well.
  * 2WikiMultiHopQA (Ho et al. 2020): 2-hop compositional + comparison +
    "inference" questions built from Wikidata triples, so the *bridge* is an
    explicit entity/relation edge and later-hop paragraphs share little surface
    text with the question. -> graph edge is reliable, lexical leakage lower.
  * MuSiQue (Trivedi et al. 2022): 2-4 hop, deliberately constructed to defeat
    disconnected-reasoning shortcuts — each hop's answer entity is the *only*
    bridge into the next paragraph, minimal lexical leakage to later hops, and
    hard distractors. -> hardest; the multi-hop graph edge is the primary
    (often only) route to the 2nd..k-th supporting fact.

The generator encodes those three profiles as knobs (hops, lexical-leakage
decay, distractor count/graph-connectivity) so the proxy preserves the property
that actually discriminates RRF from GHN: on harder datasets later-hop
supporting facts are reachable via graph edges but NOT via direct
vector/keyword similarity to the question.

Determinism: every dataset is seeded, so runs are reproducible and the
committed results JSON can be regenerated bit-for-bit.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Governed-style record-id prefix so candidate ids look like the real corpus
# (Document nodes in the governed graph). Purely cosmetic.
_DOC_PREFIX = "SYN-DOC"


@dataclass
class Document:
    doc_id: str
    tokens: List[str]                 # bag of content tokens (the "paragraph")
    entities: List[str]               # named entities mentioned (bridge anchors)


@dataclass
class Question:
    qid: str
    text_tokens: List[str]            # the question as a bag of tokens
    supporting_doc_ids: List[str]     # gold multi-hop chain (the relevant set)
    hops: int
    qtype: str                        # "bridge" | "comparison"


@dataclass
class Dataset:
    name: str
    documents: Dict[str, Document]
    questions: List[Question]
    # Undirected doc-doc edges with an edge-type label drawn from the governed
    # edge vocabulary, so the harness can weight them with GRAPH_EDGE_WEIGHTS.
    edges: List[Tuple[str, str, str]] = field(default_factory=list)


# Governed edge types (subset of lambda_function._ALLOWED_EDGE_TYPES) used to
# label the synthetic bridge edges, so GRAPH_EDGE_WEIGHTS applies unchanged.
_BRIDGE_EDGE_TYPES = ["RELATED_TO", "MENTIONS", "IMPLEMENTS", "ADDRESSES", "CHILD_OF"]


@dataclass
class Profile:
    name: str
    n_questions: int
    hop_choices: List[int]            # sampled per question
    leak: float                       # lexical leakage of later hops into the question [0,1]
    n_distractors: int                # distractor docs per question
    distractor_graph_link_prob: float # chance a distractor is graph-linked to the chain (adds noise coupling)
    comparison_frac: float            # fraction of comparison (parallel 2-entity) questions


# Profiles calibrated to the three datasets' published difficulty ordering.
PROFILES: Dict[str, Profile] = {
    "HotpotQA": Profile(
        name="HotpotQA", n_questions=100, hop_choices=[2], leak=0.55,
        n_distractors=8, distractor_graph_link_prob=0.10, comparison_frac=0.30,
    ),
    "2WikiMultiHopQA": Profile(
        name="2WikiMultiHopQA", n_questions=100, hop_choices=[2, 2, 3], leak=0.30,
        n_distractors=8, distractor_graph_link_prob=0.15, comparison_frac=0.25,
    ),
    "MuSiQue": Profile(
        name="MuSiQue", n_questions=100, hop_choices=[2, 3, 4], leak=0.12,
        n_distractors=10, distractor_graph_link_prob=0.20, comparison_frac=0.0,
    ),
}


def _vocab(rng: random.Random, prefix: str, n: int) -> List[str]:
    return [f"{prefix}{i:04d}" for i in range(n)]


def generate(profile_name: str, seed: int = 1099) -> Dataset:
    """Construct one synthetic multi-hop QA dataset for the named profile."""
    profile = PROFILES[profile_name]
    rng = random.Random(f"{profile_name}:{seed}")

    # Shared pools. Entities are the bridge anchors that create graph edges;
    # topic tokens are the surface content that drives vector/keyword signals.
    entities = _vocab(rng, "ent_", 400)
    topic_tokens = _vocab(rng, "tok_", 1200)

    documents: Dict[str, Document] = {}
    edges: List[Tuple[str, str, str]] = []
    questions: List[Question] = []
    doc_counter = 0

    def _new_doc(content: List[str], ents: List[str]) -> str:
        nonlocal doc_counter
        did = f"{_DOC_PREFIX}-{profile_name[:4].upper()}-{doc_counter:05d}"
        doc_counter += 1
        documents[did] = Document(doc_id=did, tokens=content, entities=ents)
        return did

    for q_idx in range(profile.n_questions):
        is_comparison = rng.random() < profile.comparison_frac
        hops = 2 if is_comparison else rng.choice(profile.hop_choices)
        qid = f"{profile_name[:4].upper()}-Q{q_idx:04d}"

        if is_comparison:
            # Two PARALLEL 1-hop facts about two entities the question names
            # explicitly; both supporting docs must be retrieved. A shared
            # "comparison" bridge entity links them in the graph.
            shared_ent = rng.choice(entities)
            q_tokens: List[str] = []
            support: List[str] = []
            for _ in range(2):
                subj = rng.choice(entities)
                topics = rng.sample(topic_tokens, 8)
                did = _new_doc(topics + [subj, shared_ent], [subj, shared_ent])
                support.append(did)
                # Comparison questions name both subjects + several topic words.
                q_tokens += [subj] + rng.sample(topics, 4)
            edges.append((support[0], support[1], rng.choice(_BRIDGE_EDGE_TYPES)))
            questions.append(Question(qid, q_tokens, support, hops=2, qtype="comparison"))
        else:
            # A bridge chain D0 -> D1 -> ... -> D_{hops-1}. Consecutive docs share
            # a bridge entity (=> a graph edge). The question overlaps D0 heavily;
            # each later hop leaks only `leak`-fraction of its topic tokens into
            # the question, so later hops are graph-reachable but lexically faint.
            chain: List[str] = []
            prev_bridge: Optional[str] = None
            q_tokens = []
            for hop in range(hops):
                topics = rng.sample(topic_tokens, 8)
                out_bridge = rng.choice(entities)
                ents = [out_bridge]
                if prev_bridge is not None:
                    ents.append(prev_bridge)   # incoming bridge from previous hop
                did = _new_doc(topics + ents, ents)
                chain.append(did)
                if hop == 0:
                    # First hop: strong overlap — the question is "about" D0.
                    q_tokens += rng.sample(topics, 6)
                else:
                    # Later hops: leak only a few topic tokens into the question.
                    n_leak = max(0, int(round(profile.leak * len(topics))))
                    if n_leak:
                        q_tokens += rng.sample(topics, min(n_leak, len(topics)))
                if prev_bridge is not None:
                    edges.append((chain[hop - 1], did, rng.choice(_BRIDGE_EDGE_TYPES)))
                prev_bridge = out_bridge
            questions.append(Question(qid, q_tokens, chain, hops=hops, qtype="bridge"))

        # Distractors: share some question tokens (lexical confusers) but are NOT
        # on the gold chain. Some are graph-linked to a chain doc to make the
        # graph coupling a noisy — not free — signal.
        support_now = questions[-1].supporting_doc_ids
        for _ in range(profile.n_distractors):
            shared = rng.sample(q_tokens, min(3, len(q_tokens))) if q_tokens else []
            filler = rng.sample(topic_tokens, 6)
            d_ent = [rng.choice(entities)]
            did = _new_doc(shared + filler, d_ent)
            if support_now and rng.random() < profile.distractor_graph_link_prob:
                edges.append((rng.choice(support_now), did, rng.choice(_BRIDGE_EDGE_TYPES)))

    return Dataset(name=profile_name, documents=documents, questions=questions, edges=edges)


def dataset_stats(ds: Dataset) -> Dict[str, object]:
    hop_hist: Dict[int, int] = {}
    qtype_hist: Dict[str, int] = {}
    for q in ds.questions:
        hop_hist[q.hops] = hop_hist.get(q.hops, 0) + 1
        qtype_hist[q.qtype] = qtype_hist.get(q.qtype, 0) + 1
    return {
        "name": ds.name,
        "n_documents": len(ds.documents),
        "n_questions": len(ds.questions),
        "n_edges": len(ds.edges),
        "hop_distribution": dict(sorted(hop_hist.items())),
        "qtype_distribution": qtype_hist,
        "synthetic": True,
    }
