"""ENC-TSK-I99 / ENC-FTR-104 Ph2 — GHN-vs-RRF benchmark harness.

EVALUATION-ONLY. Nothing in this package is imported by the live retrieval path
(backend/lambda/graph_query_api/lambda_function.py). The only cross-module
dependencies flow *into* this package, read-only and unmodified:

  * ``lambda_function._rrf_fuse``      — the production RRF fusion, so the RRF
                                         baseline measured here is byte-identical
                                         to production.
  * ``lambda_function.GRAPH_EDGE_WEIGHTS`` — the same per-edge-type weights the
                                         production graph signal uses.
  * ``energy_function.compute_retrieval_energy`` — the Ph1 (ENC-TSK-I98) static
                                         E(x); the GHN field h_i = -E(x)_i.

See README.md for the full design note, the honest-limitations disclosure
(synthetic datasets + offline stand-in signals, because the sandbox has no
network and the real dataset splits are unfetchable), and reproduction steps.
"""
