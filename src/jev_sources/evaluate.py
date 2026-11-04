"""Evaluation on hand-written scenarios over local fixtures (invented ".test" sites, fake web, no network).

A scenario is one answer with one claim and the expected outcome: state, and optionally the rule that must be named,
the decision code, the follow-up action, and hosts that must NEVER have been contacted or resolved.
Sets: `dev` (written while building; rules were developed against it) and `heldout` (written after the rules were
frozen, committed before its first run, run once). Malformed-policy cases check that loading fails with the named problem.

Layers are reported separately because they are different kinds of claim: the POLICY layer (allow/deny, lookalikes,
redirects, hashes, untraceable) is deterministic code; the JUDGE layer (is an approved quote supporting the claim?)
depends on the judge, offline a crude word-overlap baseline, or Jev with --live.
"""

from __future__ import annotations

import copy
import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jev_core import Judge
from jev_factcheck.demojudge import DemoJudge
from jev_factcheck.judging import default_injection_check
from jev_factcheck.loop import LoopState

from .check import parse_lenient, run_round
from .guarded import FakeWeb
from .policy import PolicyError, load_policy, parse_policy

HERE = Path(__file__).parent / "evalset"
JUDGE_STATES = ("supported", "not_supported")


@dataclass
class Row:
    id: str
    category: str
    layer: str  # policy | judge | malformed_policy
    ok: bool
    expected: dict[str, Any]
    got: dict[str, Any]
    why: str = ""


@dataclass
class Report:
    name: str
    rows: list[Row] = field(default_factory=list)

    def counts(self, layer: str | None = None) -> tuple[int, int]:
        rows = [r for r in self.rows if layer in (None, r.layer)]
        return sum(r.ok for r in rows), len(rows)


def load_web() -> dict[str, Any]:
    raw = json.loads((HERE / "web.json").read_text(encoding="utf-8"))
    return {k: tuple(v) if isinstance(v, list) else v for k, v in raw.items()}


def load_set(name: str) -> dict[str, Any]:
    return json.loads((HERE / f"{name}.json").read_text(encoding="utf-8"))


def eval_policy():
    return load_policy(HERE / "policy.toml")


def run_scenario(scn: dict[str, Any], judge: Judge, policy=None) -> Row:
    policy = policy or eval_policy()
    web = FakeWeb(copy.deepcopy(load_web()))
    cf, untr = parse_lenient({"text": "", "claims": scn["claims"]})
    out = run_round(cf, untr, policy, web.fetcher(policy), judge, LoopState(), injection_check=default_injection_check())
    res = out.results[0]
    exp = scn["expect"]
    got: dict[str, Any] = {"state": res.state, "action": res.action, "reason": res.reason,
                           "rule": next((f[5:] for f in res.source_flags if f.startswith("rule:")), "")}
    problems = []
    if got["state"] != exp["state"]:
        problems.append(f"state {got['state']} != {exp['state']}")
    if "rule" in exp and got["rule"] != exp["rule"]:
        problems.append(f"rule {got['rule']} != {exp['rule']}")
    if "code" in exp and got["reason"] != exp["code"]:
        problems.append(f"code {got['reason']} != {exp['code']}")
    if "action" in exp and got["action"] != exp["action"]:
        problems.append(f"action {got['action']} != {exp['action']}")
    for host in exp.get("not_contacted", []):
        if any(f"//{host}/" in u or f"//{host}:" in u for u in web.contacted) or host in web.resolved:
            problems.append(f"{host} was contacted")
    if exp["state"] in ("forbidden_source",) and exp.get("rule") and exp["rule"] not in res.explanation:
        problems.append("explanation does not name the rule")
    layer = "judge" if exp["state"] in JUDGE_STATES else "policy"
    return Row(scn["id"], scn["category"], layer, not problems, exp, got, "; ".join(problems))


def run_policy_case(case: dict[str, Any]) -> Row:
    import tomllib

    try:
        parse_policy(tomllib.loads(case["toml"]))
        got, ok, why = "loaded", False, "an invalid policy was accepted"
    except PolicyError as exc:
        got = "; ".join(exc.errors)
        ok = case["expect_error"] in got
        why = "" if ok else f"error text lacks {case['expect_error']!r}"
    return Row(case["id"], case["category"], "malformed_policy", ok, {"error_contains": case["expect_error"]}, {"error": got}, why)


def run_set(name: str, judge: Judge | None = None) -> Report:
    data = load_set(name)
    judge = judge or DemoJudge()
    rep = Report(name)
    policy = eval_policy()
    rep.rows += [run_scenario(s, judge, policy) for s in data["scenarios"]]
    rep.rows += [run_policy_case(c) for c in data.get("policies", [])]
    return rep


def wilson_lower(k: int, n: int, z: float = 1.96) -> float:
    if n == 0:
        return 0.0
    p = k / n
    d = 1 + z * z / n
    return (p + z * z / (2 * n) - z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / d


def format_report(rep: Report, judge_name: str) -> str:
    k, n = rep.counts()
    lines = [f"set {rep.name} (judge: {judge_name}): {k}/{n} scenarios as expected (95% lower bound {wilson_lower(k, n):.0%})"]
    for layer in ("policy", "judge", "malformed_policy"):
        a, b = rep.counts(layer)
        if b:
            lines.append(f"  {layer:17s} {a}/{b}")
    cats: dict[str, list[Row]] = {}
    for r in rep.rows:
        cats.setdefault(r.category, []).append(r)
    lines.append("  by category: " + ", ".join(f"{c} {sum(r.ok for r in rs)}/{len(rs)}" for c, rs in cats.items()))
    for r in rep.rows:
        if not r.ok:
            lines.append(f"  FAIL {r.id} [{r.category}/{r.layer}]: {r.why}")
    return "\n".join(lines)
