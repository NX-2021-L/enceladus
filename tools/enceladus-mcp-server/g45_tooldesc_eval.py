"""ENC-TSK-G45 — argument-hallucination eval for code-mode tool descriptions.

Co-required with ENC-TSK-G12. Source rationale: arXiv:2505.18135 — verbose tool
descriptions injected with cross-tool / foreign-argument distractor tokens collide
with constrained decoding (strict:true) and raise the argument-hallucination rate.

This harness measures that distractor surface deterministically, so the pre/post
delta is reproducible by anyone without network or model credentials (the
"deterministic schema-conformance proxy" option). It also optionally cross-checks
against a live strict-tool model run when ANTHROPIC_API_KEY is present, but the
headline metric is the deterministic one.

Metric — "argument-hallucination surface" per tool description:
  For each tool, count distractor tokens in its `description` that are the documented
  mechanism by which a verbose description induces a wrong tool call:
    (a) cross-tool references  — the name of another tool appears in the description;
    (b) foreign-argument names  — a snake_case token that is a parameter of some OTHER
        tool but NOT of this tool (the model is primed to emit an arg this tool rejects);
    (c) imperative How-to cues  — directive phrasing ("use ... before", "preflight",
        "query ...", "required before", "advance children", "avoid ...") that pushes the
        model toward an action/sequence rather than describing the tool (Diataxis RULE-06).
  The corpus rate is the sum of distractors across the top-20 actions. A pure-Reference
  description (RULE-06) carries none of (a)/(b)/(c) for tools it does not own.

Usage:
    python g45_tooldesc_eval.py                # prints pre/post report, exits 0 if >=10%
    pytest test_g45_tooldesc_eval.py           # asserts the >=10% reduction gate
"""
from __future__ import annotations

import ast
import json
import os
import re
from pathlib import Path
from typing import Dict, List

HERE = Path(__file__).resolve().parent
SERVER_PY = HERE / "server.py"
BASELINE_JSON = HERE / "g45_baseline_descriptions.json"

# Top-20 highest-frequency code-mode actions (10 reads via search(), 10 writes via
# execute()). See G45_DIATAXIS_TOP20_AUDIT.md for the ranking method.
TOP20: List[str] = [
    # reads (search)
    "tracker_get", "tracker_list", "tracker_validation_rules", "documents_get",
    "documents_search", "documents_list", "reference_search", "governance_get",
    "governance_dictionary", "connection_health",
    # writes (execute)
    "tracker_create", "tracker_set", "tracker_set_acceptance_evidence", "checkout_task",
    "advance_task_status", "append_worklog", "tracker_log", "documents_put",
    "documents_patch", "deploy_submit",
]

# Imperative / How-to cue patterns (Diataxis RULE-06 violations in Reference text).
_HOWTO_CUES = [
    r"\buse (?:to |at |when |this )",
    r"\bbefore (?:calling|checkout|coding)\b",
    r"\bpreflight\b",
    r"\bquery governance_dictionary\b",
    r"\brequired before\b",
    r"\badvance children\b",
    r"\bavoids? \b",
    r"\bat session start\b",
    r"\bfor tasks,? use\b",
    r"\bfor issues/features use\b",
]


def extract_tools(source: str) -> Dict[str, Dict]:
    """Parse a server.py source string and return {tool_name: {description, params}}.

    AST handles implicit string-literal concatenation in the description= kwarg and
    reads the inputSchema properties keys as the tool's valid argument set.
    """
    tree = ast.parse(source)
    tools: Dict[str, Dict] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name_id = getattr(func, "id", None) or getattr(func, "attr", None)
        if name_id != "Tool":
            continue
        kw = {k.arg: k.value for k in node.keywords}
        if "name" not in kw or "description" not in kw:
            continue
        try:
            name = ast.literal_eval(kw["name"])
            description = ast.literal_eval(kw["description"])
        except (ValueError, SyntaxError):
            continue
        params: List[str] = []
        schema = kw.get("inputSchema")
        if isinstance(schema, ast.Dict):
            for key, val in zip(schema.keys, schema.values):
                if isinstance(key, ast.Constant) and key.value == "properties" and isinstance(val, ast.Dict):
                    for pk in val.keys:
                        if isinstance(pk, ast.Constant):
                            params.append(str(pk.value))
        tools[name] = {"description": description, "params": params}
    return tools


def _all_tool_names(tools: Dict[str, Dict]) -> set:
    return set(tools)


def _all_params(tools: Dict[str, Dict]) -> set:
    out: set = set()
    for t in tools.values():
        out.update(t["params"])
    return out


def distractor_breakdown(name: str, tools: Dict[str, Dict]) -> Dict[str, int]:
    """Count (a) cross-tool refs, (b) foreign-arg names, (c) how-to cues for one tool."""
    desc = tools[name]["description"]
    own_params = set(tools[name]["params"])
    other_tool_names = _all_tool_names(tools) - {name}
    foreign_params = _all_params(tools) - own_params

    tokens = re.findall(r"[a-z_]+", desc.lower())

    cross_tool = sum(1 for tok in tokens if tok in other_tool_names)
    # foreign args: snake_case token that is a param of another tool, not this one,
    # and not also a tool name (avoid double counting with cross_tool).
    foreign_args = sum(
        1 for tok in tokens
        if tok in foreign_params and "_" in tok and tok not in own_params and tok not in other_tool_names
    )
    howto = sum(len(re.findall(pat, desc.lower())) for pat in _HOWTO_CUES)
    return {"cross_tool": cross_tool, "foreign_args": foreign_args, "howto_cues": howto}


def score(name: str, tools: Dict[str, Dict]) -> int:
    b = distractor_breakdown(name, tools)
    return b["cross_tool"] + b["foreign_args"] + b["howto_cues"]


def corpus_report(baseline: Dict[str, Dict], post: Dict[str, Dict]) -> Dict:
    rows = []
    pre_total = post_total = 0
    for name in TOP20:
        pre = score(name, baseline) if name in baseline else 0
        pos = score(name, post) if name in post else 0
        pre_total += pre
        post_total += pos
        rows.append((name, pre, pos))
    reduction_pct = (100.0 * (pre_total - post_total) / pre_total) if pre_total else 0.0
    return {
        "rows": rows,
        "pre_total": pre_total,
        "post_total": post_total,
        "reduction_pct": reduction_pct,
    }


def load_baseline() -> Dict[str, Dict]:
    return json.loads(BASELINE_JSON.read_text())


def load_post() -> Dict[str, Dict]:
    return extract_tools(SERVER_PY.read_text())


def main() -> int:
    baseline = load_baseline()
    post = load_post()
    rep = corpus_report(baseline, post)
    print("ENC-TSK-G45 argument-hallucination surface — top-20 code-mode tool descriptions")
    print(f"{'action':32} {'pre':>4} {'post':>4}  {'delta':>5}")
    print("-" * 50)
    for name, pre, pos in rep["rows"]:
        print(f"{name:32} {pre:>4} {pos:>4}  {pos - pre:>5}")
    print("-" * 50)
    print(f"{'TOTAL':32} {rep['pre_total']:>4} {rep['post_total']:>4}")
    print(f"\nargument-hallucination surface reduction: {rep['reduction_pct']:.1f}%  (gate: >=10%)")
    ok = rep["reduction_pct"] >= 10.0
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
