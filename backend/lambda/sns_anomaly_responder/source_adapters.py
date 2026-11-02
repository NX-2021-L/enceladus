"""Source-adapter boundary for the anomaly -> governed-issue primitive
(ENC-TSK-R82-0D / ENC-FTR-150 AC-8; BRD DOC-8E2CFF602B33 section 6 v5 seam).

The primitive in ``lambda_function`` (dedupe lookup -> idempotent create / replay refresh ->
notify -> enrich) is SOURCE-AGNOSTIC. Everything source-specific lives behind one adapter per
source, selected through the registry below. Adding a source (MENTIONS drift, weekly magnitude
digest, v5 capture-plane events) means writing an adapter module and calling
``REGISTRY.register(adapter)``; the primitive is never edited.

ADAPTER CONTRACT
----------------
An adapter is any object (module or class) providing:

    SOURCE: str                          # registry key; lower-case, no ':' (it prefixes the dedupe key)
    parse(message: str) -> list[dict]    # raw SNS Message body -> NormalizedAnomaly list

Rules every adapter must satisfy (enforced by ``validate_normalized``):

* Deterministic, no network, no LLM. Thresholding/suppression is the adapter's job: ``parse``
  returns only anomalies that should become (or refresh) an issue; non-matching or malformed
  bodies yield ``[]``.
* STABLE ``anomaly_id``: derived only from the source's own identity for the signal (a CAD
  anomalyId, a drift signature hash), never from wall-clock time, payload ordering or impact
  amounts. The primitive dedupes on ``"{source}:{anomaly_id}"``; an unstable id mints duplicates.
* ``source`` equals the adapter's ``SOURCE``.
* PROJECT ROUTING HOOK: ``project`` (alias ``project_id``) is the tracker project the issue is
  filed under. The adapter chooses it (default via its own env var / constant); enrichment may
  only PROPOSE a re-route, never move the record.
* ``title`` should carry the token ``[{source}:{anomaly_id}]`` so the dedupe lookup survives an
  ID-Service outage; ``evidence`` is a non-empty list of dicts satisfying the issue-create
  evidence contract (``description`` + ``steps_to_duplicate`` list); the
  ``source_key`` lookup field is NOT added for you: adapters set ``evidence[].source_key``
  to ``"{source}:{anomaly_id}"`` themselves (see aws_cad_adapter / stub_adapter).

NormalizedAnomaly keys: source, anomaly_id, project (+project_id alias), title, evidence[],
impact{}, breakdown[], severity, priority, category, raw_ref (opaque pointer back to the raw
payload, e.g. a details URL; never the payload itself).
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Protocol, TypedDict, runtime_checkable


class NormalizedAnomaly(TypedDict, total=False):
    source: str
    anomaly_id: str
    project: str
    project_id: str
    title: str
    evidence: List[Dict[str, Any]]
    impact: Dict[str, Any]
    breakdown: List[Dict[str, Any]]
    severity: str
    priority: str
    category: str
    raw_ref: Any


@runtime_checkable
class SourceAdapter(Protocol):
    SOURCE: str

    def parse(self, message: str) -> List[NormalizedAnomaly]:  # pragma: no cover - protocol
        ...


class AdapterContractError(ValueError):
    """An adapter returned something the source-agnostic primitive cannot safely consume."""


_SOURCE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_REQUIRED = ("source", "anomaly_id", "project", "title", "evidence")


def validate_normalized(norm: Any, source: str) -> Dict[str, Any]:
    """Check one normalized anomaly against the contract and fill the ``project_id`` alias.
    Returns the same dict (mutated only to add ``project_id``). Raises AdapterContractError."""
    if not isinstance(norm, dict):
        raise AdapterContractError(f"{source}: adapter returned non-dict anomaly")
    missing = [k for k in _REQUIRED if not norm.get(k)]
    if missing:
        raise AdapterContractError(f"{source}: normalized anomaly missing {missing}")
    if norm["source"] != source:
        raise AdapterContractError(f"{source}: anomaly source {norm['source']!r} != adapter SOURCE")
    if not str(norm["anomaly_id"]).strip():
        raise AdapterContractError(f"{source}: anomaly_id must be a non-empty stable id")
    ev = norm["evidence"]
    if not isinstance(ev, list) or not all(isinstance(e, dict) for e in ev):
        raise AdapterContractError(f"{source}: evidence must be a non-empty list of dicts")
    norm.setdefault("project_id", norm["project"])
    return norm


class AdapterRegistry(dict):
    """source -> adapter. A dict subclass so existing ``ADAPTERS[...]`` / ``.get`` / ``.pop``
    call sites keep working; ``register`` adds the contract checks."""

    def register(self, adapter: Any) -> Any:
        source = getattr(adapter, "SOURCE", None)
        if not isinstance(source, str) or not _SOURCE_RE.match(source):
            raise AdapterContractError(f"adapter {adapter!r} needs a lower-case SOURCE without ':'")
        if not callable(getattr(adapter, "parse", None)):
            raise AdapterContractError(f"adapter {source} needs parse(message)")
        self[source] = adapter
        return adapter

    def sources(self) -> List[str]:
        return sorted(self)

    def resolve(self, source: Optional[str], default: str) -> Any:
        """Adapter for `source`, else the default source's adapter (unknown source never breaks
        intake of the default feed)."""
        return self.get(source or default) or self[default]


def parse_message(adapter: Any, message: str) -> List[Dict[str, Any]]:
    """Run an adapter and enforce the contract on every anomaly it returns."""
    source = getattr(adapter, "SOURCE", "")
    out: List[Dict[str, Any]] = []
    for norm in adapter.parse(message) or []:
        out.append(validate_normalized(norm, source))
    return out


def build_default_registry(extra: Iterable[Any] = ()) -> AdapterRegistry:
    import aws_cad_adapter  # local import: keeps this module import-cycle free

    reg = AdapterRegistry()
    reg.register(aws_cad_adapter)
    for adapter in extra:
        reg.register(adapter)
    return reg


REGISTRY = build_default_registry()
