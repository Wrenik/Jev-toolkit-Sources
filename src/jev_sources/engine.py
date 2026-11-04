"""Apply a policy to one URL. Deterministic, no network, no model. Default is deny; deny beats allow.

Every decision names the rule that decided it (`rule_id`; built-in checks use ids like `builtin/default-deny`)
and, for a rejection, lists what would have been allowed. All text here is built from validated policy fields
(ids, hosts, prefixes), never from the free-text `note`, so a decision is safe to show to an LLM.
"""

from __future__ import annotations

import difflib
import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from .policy import Policy, Rule
from .urlcanon import Canon, UrlRejected, canonicalize

NEAR_MISS_RATIO = 0.82


@dataclass
class Decision:
    allowed: bool
    code: str  # allowed | not_on_allowlist | denied_by_rule | url_form | wrapper | docset_modified | ...
    rule_id: str
    message: str
    url: str = ""  # canonical text of the URL that was judged
    allowed_instead: list[str] = field(default_factory=list)
    overlapping_allow: list[str] = field(default_factory=list)
    jurisdiction: str = ""
    content: bytes | None = field(default=None, repr=False)  # docset bytes that were hashed (no re-read, no race)

    def to_dict(self) -> dict:
        return {"allowed": self.allowed, "code": self.code, "rule": self.rule_id, "message": self.message,
                "url": self.url, "allowed_instead": self.allowed_instead, "jurisdiction": self.jurisdiction}


def _match(rule: Rule, c: Canon, fold: bool = False) -> bool:
    """`fold`: compare paths case-insensitively. Used for deny rules: many servers (IIS, Windows, some CMS) serve
    /Private/ and /private/ as the same resource, so a deny must not be bypassable by case. Allow rules stay exact."""
    if rule.kind == "docset":
        return c.kind == "docset" and c.docset == rule.docset
    if c.kind != "web":
        return False
    if rule.kind == "domain" and rule.suffix:
        return c.host.endswith("." + rule.host)  # never the suffix itself, only names registered under it
    if rule.kind == "domain":
        return c.host == rule.host or (rule.subdomains and c.host.endswith("." + rule.host))
    if c.host != rule.host:
        return False
    p, rp = (c.path.rstrip("/") or ""), rule.prefix_path
    if fold:  # also drop ";param" suffixes per segment: Tomcat and others read /private;x=1 as /private
        p, rp = "/".join(seg.split(";", 1)[0] for seg in p.lower().split("/")), rp.lower()
    # the bare prefix itself (".../law" for prefix ".../law/") counts as the directory and is matched deliberately
    return rp == "" or p == rp or p.startswith(rp + "/")


def _deny(policy: Policy, code: str, rule_id: str, why: str, c: Canon | None, url: str = "", instead: bool = True) -> Decision:
    allowed = policy.allowed_summary() if instead else []
    tail = (" Allowed instead: " + "; ".join(allowed) + ".") if allowed else ""
    return Decision(False, code, rule_id, f"Rejected by rule {rule_id}: {why}.{tail}", c.text() if c else url, allowed)


def _near_miss(policy: Policy, host: str) -> str:
    hosts = sorted({r.host for r in policy.allows if r.host and policy.active(r)})
    if host in hosts:
        return ""
    close = difflib.get_close_matches(host, hosts, n=1, cutoff=NEAR_MISS_RATIO)
    for h in hosts:  # a host that merely contains an allowed name, e.g. allowed.example.evil.example
        if host.startswith(h + ".") or (h in host and not host.endswith("." + h)):
            close = [h]
    return f"; it looks similar to the allowed host {close[0]} but is a different host" if close else ""


def evaluate(policy: Policy, url: str, *, check_files: bool = True, _depth: int = 0) -> Decision:
    try:
        c = canonicalize(url)
    except UrlRejected as exc:
        return _deny(policy, f"url_{exc.code}", "builtin/url-form", f"the URL cannot be judged ({exc.code}: {exc.detail or 'malformed'})", None, str(url)[:200])
    return _evaluate_canon(policy, c, check_files, _depth)


def _evaluate_canon(policy: Policy, c: Canon, check_files: bool, depth: int) -> Decision:
    if c.kind == "web":
        wrapped = c.inner is not None or c.wrapper not in ("", "redirect")
        if wrapped:
            if not policy.allow_archives:
                return _deny(policy, "wrapper", "builtin/wrapper",
                             f"{c.host} is a {c.wrapper} service that serves or redirects to another URL; cite the original page itself", c)
            if c.inner is None or depth >= 2:
                return _deny(policy, "wrapper", "builtin/wrapper", f"the {c.wrapper} URL does not reveal a checkable original URL", c)
            inner = _evaluate_canon(policy, c.inner, check_files, depth + 1)
            if not inner.allowed:
                inner.message = f"Wrapped URL ({c.host}) -> " + inner.message
            return inner
        if c.port != (443 if c.scheme == "https" else 80):
            return _deny(policy, "port", "builtin/port", f"port {c.port} is not allowed for {c.scheme} (only its default port)", c)
    for rule in policy.denies:
        if _match(rule, c, fold=True):
            allow_also = [r.id for r in policy.allows if _match(r, c)]
            d = _deny(policy, "denied_by_rule", rule.id, f"{rule.describe()} is denied", c)
            d.overlapping_allow = allow_also
            if allow_also:
                d.message += f" (allow rule {', '.join(allow_also)} also matches; deny wins)"
            return d
    matched = [r for r in policy.allows if _match(r, c)]
    if not matched:
        why = f"{c.host if c.kind == 'web' else 'docset ' + c.docset} is not on the allowlist (default is deny)"
        if c.kind == "web":
            if c.non_ascii_host:
                why += f"; the host contains non-ASCII characters and is {c.host} in its real form, which may be a lookalike"
            if any(r.host == c.host and r.kind == "url_prefix" and policy.active(r) for r in policy.allows):
                why += f"; the host {c.host} has approved path prefixes, but this path is under none of them"
            why += _near_miss(policy, c.host)
        return _deny(policy, "not_on_allowlist", "builtin/default-deny", why, c)
    active = [r for r in matched if policy.active(r)]
    if not active:
        r = matched[0]
        return _deny(policy, "jurisdiction_not_active", r.id,
                     f"{r.describe()} is approved only for jurisdiction {r.jurisdiction}, but the active jurisdictions are {', '.join(policy.jurisdictions)}", c)
    if c.kind == "web" and c.scheme == "http":
        ok = [r for r in active if r.allow_http]
        if not ok:
            return _deny(policy, "insecure_scheme", active[0].id, f"rule {active[0].id} approves https only; this URL uses http", c)
        active = ok
    rule = active[0]
    if c.kind == "docset":
        d = _check_docset(policy, c, rule, check_files)
        if d is not None:
            return d
    for emb in c.embedded:  # open redirector: an approved page that forwards to a URL in its query string
        inner = _evaluate_canon(policy, emb, False, depth + 1)
        if not inner.allowed:
            return _deny(policy, "embedded_url", inner.rule_id,
                         f"this approved-host URL carries another URL ({emb.host}) in its query string, which is how open redirectors forward to other sites, and that one is not allowed ({inner.code})", c)
    return Decision(True, "allowed", rule.id, f"Allowed by rule {rule.id} ({rule.describe()}).", c.text(), jurisdiction=rule.jurisdiction)


def _check_docset(policy: Policy, c: Canon, rule: Rule, check_files: bool) -> Decision | None:
    ds = policy.docsets[c.docset]
    expect = ds.files.get(c.relpath)
    if expect is None:
        return _deny(policy, "not_in_manifest", rule.id, f"{c.relpath} is not in the approved file list of document set {ds.id}", c)
    if not check_files:
        return None
    path = (ds.root / c.relpath).resolve()
    if ds.root not in path.parents or not path.is_file():
        return _deny(policy, "docset_file_missing", rule.id, f"{c.relpath} is in the manifest of {ds.id} but the file is missing or outside the folder", c)
    data = path.read_bytes()
    got = hashlib.sha256(data).hexdigest()
    if got != expect:
        return _deny(
            policy, "docset_modified", rule.id,
            f"{c.relpath} changed after it was approved (manifest sha256 {expect[:12]}..., file now {got[:12]}...). It fails closed. "
            f"To re-approve: read the new version, run `python -m jev_sources hash <folder>`, paste the new hash into the policy, bump [policy].version and add a [[changelog]] entry",
            c, instead=False)
    return Decision(True, "allowed", rule.id, f"Allowed by rule {rule.id} ({rule.describe()}; sha256 verified).", c.text(),
                    jurisdiction=rule.jurisdiction, content=data)


def sha256_manifest(folder: str | Path, patterns: tuple[str, ...] = (".txt", ".md", ".html", ".htm")) -> dict[str, str]:
    """{relative posix path: sha256} for the documents in a folder; the input to a policy's [[docset]] files table."""
    root = Path(folder).resolve()
    out: dict[str, str] = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix.lower() in patterns and root in p.resolve().parents:  # skip links that leave the folder
            out[p.relative_to(root).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out
