"""`explain <url>`: show, step by step, what the policy does with one URL and why. Offline, read-only, no model."""

from __future__ import annotations

from .engine import _match, evaluate
from .policy import Policy, Rule
from .urlcanon import Canon, UrlRejected, canonicalize


def _why_not(rule: Rule, c: Canon) -> str:
    if rule.kind == "docset":
        return f"not a document of set {rule.docset}"
    if c.kind != "web":
        return "not a web URL"
    if rule.kind == "domain":
        if rule.suffix:
            return f"host {c.host} is not registered under the suffix {rule.host} (the suffix itself is not a site)"
        if rule.subdomains:
            return f"host {c.host} is neither {rule.host} nor a subdomain of it"
        return f"host {c.host} is not {rule.host} (subdomains are not included; add subdomains = true to include them)"
    if c.host != rule.host:
        return f"host {c.host} is not {rule.host}"
    return f"path {c.path} is not under {rule.prefix_path or '/'} (a prefix matches whole path segments only)"


def explain(policy: Policy, url: str) -> str:
    out = [f"Policy:     {policy.name} {policy.version}", f"Input:      {url}"]
    d = evaluate(policy, url)
    try:
        c = canonicalize(url)
    except UrlRejected as exc:
        out.append(f"Canonical:  (none) rejected before any rule is looked at: {exc.code}: {exc.detail or 'malformed'}")
        return "\n".join(out + ["", f"Decision:   REJECTED by {d.rule_id}", f"            {d.message}"])
    out.append(f"Canonical:  {c.text()}")
    if c.kind == "web":
        notes = []
        if c.non_ascii_host:
            notes.append(f"the host has non-ASCII characters; its real (punycode) form is {c.host}")
        if c.wrapper:
            notes.append(f"{c.host} is a {c.wrapper} service" + (f" wrapping {c.inner.text()}" if c.inner else ""))
        notes += [f"the query string carries another URL: {e.text()}" for e in c.embedded]
        out += [f"Note:       {n}" for n in notes]
    out.append("Rules:")
    for rule in [*policy.denies, *policy.allows]:
        hit = _match(rule, c, fold=rule.effect == "deny")
        extra = ""
        if hit and rule.effect == "allow" and not policy.active(rule):
            extra = f"  (inactive: approved only for jurisdiction {rule.jurisdiction})"
        elif not hit:
            extra = f"  ({_why_not(rule, c)})"
        out.append(f"  {'MATCH   ' if hit else 'no match'} {rule.effect:5} {rule.id}: {rule.describe()}{extra}")
    out += ["", f"Decision:   {'ALLOWED' if d.allowed else 'REJECTED'} by {d.rule_id}", f"            {d.message}"]
    if not d.allowed and d.code == "not_on_allowlist":
        out.append("            To allow it, a person adds an [[allow]] rule, bumps the policy version and adds a changelog line.")
    return "\n".join(out)
