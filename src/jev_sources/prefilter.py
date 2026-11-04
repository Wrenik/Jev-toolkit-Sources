"""Pre-filter (what retrieval may return) and the Claude Code PreToolUse hook (what the agent may open).

Pre-filter: `filter_results` keeps only approved results. What the model receives for a removed result is nothing,
only a count; the per-rule reasons go to a log file for the human (a model must not learn titles/snippets of
forbidden pages, and the rule list is the user's business). Allowed results pass through unchanged.

Hook: a PreToolUse hook for WebFetch/WebSearch. It defaults to MONITOR mode: it logs what it would have blocked and
lets the call through, because tools that block without warning get switched off. Enforcement is an explicit switch
(`--enforce` or JEV_SOURCES_MODE=enforce). In enforce mode a blocked call exits 2 with a one-line reason on stderr.
It never contacts the network. It cannot see redirects (the WebFetch tool follows them itself), model memory, or
tools such as Bash: those are covered only after the fact by `check`.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from .engine import Decision, evaluate
from .policy import Policy, PolicyError, load_policy
from .urlcanon import UrlRejected, canonicalize

ALLOW_ONCE_TTL = 600  # seconds
HOOK_TOOLS = ("WebFetch", "WebSearch")


def filter_results(policy: Policy, items: list[Any]) -> tuple[list[Any], list[tuple[Any, Decision]]]:
    kept: list[Any] = []
    removed: list[tuple[Any, Decision]] = []
    for it in items:
        url = it.get("url") if isinstance(it, dict) else None
        d = (
            evaluate(policy, url)
            if isinstance(url, str)
            else Decision(False, "url_missing", "builtin/url-form", "result has no URL")
        )
        (kept if d.allowed else removed).append(it if d.allowed else (it, d))
    return kept, removed


def filter_json(policy: Policy, data: Any, log_path: str | Path | None = None) -> dict[str, Any]:
    items = data.get("results") if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise ValueError("expected a list of results, or an object with a 'results' list")
    kept, removed = filter_results(policy, items)
    if log_path and removed:
        p = Path(log_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as fh:
            for it, d in removed:
                fh.write(
                    json.dumps(
                        {
                            "time": int(time.time()),
                            "policy": f"{policy.name} {policy.version}",
                            "url": str(it.get("url", ""))[:300] if isinstance(it, dict) else "",
                            "rule": d.rule_id,
                            "code": d.code,
                        }
                    )
                    + "\n"
                )
    out: dict[str, Any] = {"results": kept, "removed_by_policy": len(removed)}
    if removed:
        out["note"] = (
            f"{len(removed)} result(s) were removed by the source policy and are not available. Use only the results listed."
        )
    return out


# ---- allow once (human action) -----------------------------------------------------------------------------


def _key(url: str) -> str:
    try:
        text = canonicalize(url).text()
    except UrlRejected:
        text = url
    return hashlib.sha256(text.split("?", 1)[0].encode()).hexdigest()  # the query is not part of the grant


def grant_once(var_dir: Path, url: str, now: float | None = None) -> None:
    p = var_dir / "sources-allow-once.json"
    now = time.time() if now is None else now
    grants = [g for g in _load_grants(p) if g["until"] > now]
    grants.append({"key": _key(url), "until": now + ALLOW_ONCE_TTL})
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(grants), encoding="utf-8")


def _load_grants(p: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return [g for g in data if isinstance(g, dict) and "key" in g and "until" in g]
    except (OSError, ValueError):
        return []


def _consume(var_dir: Path, url: str, now: float) -> bool:
    p = var_dir / "sources-allow-once.json"
    grants = [g for g in _load_grants(p) if g["until"] > now]
    k = _key(url)
    hit = next((g for g in grants if g["key"] == k), None)
    if hit:
        grants.remove(hit)
        p.write_text(json.dumps(grants), encoding="utf-8")
    return hit is not None


# ---- the hook ---------------------------------------------------------------------------------------------


def _log(var_dir: Path, rec: dict[str, Any]) -> None:
    try:
        var_dir.mkdir(parents=True, exist_ok=True)
        with (var_dir / "sources-hook.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError:
        pass  # logging must never break the tool call


def _safe_url(url: str) -> str:
    return url.split("?", 1)[0][:300]  # query strings can carry tokens


def run_hook(
    stdin_text: str,
    policy_path: str | Path,
    *,
    enforce: bool = False,
    var_dir: str | Path = "var",
    now: float | None = None,
) -> tuple[int, str]:
    """Returns (exit code, message for stderr). 0 = let the call through, 2 = block (Claude Code shows stderr to the model)."""
    now = time.time() if now is None else now
    var = Path(var_dir)
    try:
        event = json.loads(stdin_text)
        tool = event.get("tool_name", "")
        tin = event.get("tool_input") or {}
    except (ValueError, AttributeError):
        return (2, "jev-sources: unreadable hook input; blocked (fail closed).") if enforce else (0, "")
    if tool not in HOOK_TOOLS:
        return 0, ""
    mode = "enforce" if enforce else "monitor"
    try:
        policy = load_policy(policy_path)
    except PolicyError as exc:
        msg = f"jev-sources: the source policy cannot be loaded ({exc.errors[0]}); " + (
            "all web access is blocked until it is fixed." if enforce else "monitor mode lets the call through."
        )
        _log(
            var,
            {"time": int(now), "mode": mode, "tool": tool, "decision": "policy_error", "error": exc.errors[0][:200]},
        )
        return (2, msg) if enforce else (0, msg)
    if tool == "WebSearch":
        if policy.web_search == "allow":
            return 0, ""
        why = (
            "web search results cannot be filtered by the source policy (policy.web_search = block); "
            "open approved URLs directly, or run `python -m jev_sources filter` on retrieval results"
        )
        _log(var, {"time": int(now), "mode": mode, "tool": tool, "decision": "block", "rule": "builtin/web-search"})
        if enforce and not _consume(var, "websearch", now):
            return (
                2,
                f"Blocked by source policy {policy.name} v{policy.version}: {why}. A person can allow one search: python -m jev_sources allow-once websearch",
            )
        return 0, f"[monitor] jev-sources would block this WebSearch: {why}." if not enforce else ""
    url = str(tin.get("url", ""))
    d = evaluate(policy, url, check_files=False)
    _log(
        var,
        {
            "time": int(now),
            "mode": mode,
            "tool": tool,
            "url": _safe_url(url),
            "decision": "allow" if d.allowed else "block",
            "rule": d.rule_id,
            "code": d.code,
        },
    )
    if d.allowed:
        return 0, ""
    line = f"{d.message} A person can allow this once with: python -m jev_sources allow-once {_safe_url(url)}"
    if not enforce:
        return 0, f"[monitor] jev-sources would block this call. {line}"
    if _consume(var, url, now):
        return 0, ""
    return 2, f"Blocked by source policy {policy.name} v{policy.version}. {line}"


def env_mode() -> bool:
    return os.environ.get("JEV_SOURCES_MODE", "monitor").lower() == "enforce"
