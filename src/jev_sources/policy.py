"""The allowlist policy file: a human-readable, versioned TOML document that is DATA, never instructions.

Layout (see docs/SOURCE_RESTRICTION.md for a full example):

    [policy]              name, version, jurisdictions (optional list), allow_archives, web_search
    [[changelog]]         version, date, note        (the current version must have an entry)
    [[allow]] / [[deny]]  id + exactly one of: host (+subdomains) | prefix | docset; optional jurisdiction/canonical/note
    [[docset]]            id, root (folder, relative to the policy file), files = { "rel/path" = "sha256" }

Everything that can ever be shown to a model or a judge (ids, hosts, prefixes, docset names) is validated against a
strict character set, so a policy cannot smuggle sentences into a prompt. Free text (`note`, changelog notes) is
length-limited and shown to humans only; it is never put into a judge state or a correction message.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .urlcanon import UrlRejected, canonical_host, canonicalize

ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$")
VERSION_RE = re.compile(r"^\d{1,4}\.\d{1,4}\.\d{1,4}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
JUR_RE = re.compile(r"^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})?$")
NOTE_MAX = 200

_POLICY_KEYS = {"name", "version", "jurisdictions", "allow_archives", "web_search"}
_RULE_KEYS = {"id", "host", "subdomains", "prefix", "docset", "jurisdiction", "canonical", "note", "allow_http"}
_DOCSET_KEYS = {"id", "root", "files", "note"}
_CHANGELOG_KEYS = {"version", "date", "note"}


class PolicyError(ValueError):
    """The policy file is invalid. `errors` lists every problem, each naming the rule or key."""

    def __init__(self, errors: list[str]):
        super().__init__("policy is invalid:\n  - " + "\n  - ".join(errors))
        self.errors = errors


@dataclass(frozen=True)
class Rule:
    id: str
    effect: str  # allow | deny
    kind: str  # domain | url_prefix | docset
    host: str = ""  # canonical (punycode) host for domain rules, or the host of a prefix rule
    subdomains: bool = False
    prefix_path: str = ""  # url_prefix: path without trailing slash ("" = whole host)
    prefix_scheme: str = "https"
    docset: str = ""
    jurisdiction: str = ""
    canonical: str = ""
    allow_http: bool = False
    note: str = ""

    def describe(self) -> str:
        if self.kind == "domain":
            return f"domain {self.host}" + (" (and its subdomains)" if self.subdomains else "")
        if self.kind == "url_prefix":
            return f"URLs under {self.prefix_scheme}://{self.host}{self.prefix_path}/"
        return f"document set {self.docset}"


@dataclass(frozen=True)
class DocSet:
    id: str
    root: Path
    files: dict[str, str]  # relative posix path -> sha256 (lowercase hex)


@dataclass
class Policy:
    name: str
    version: str
    rules: list[Rule] = field(default_factory=list)
    docsets: dict[str, DocSet] = field(default_factory=dict)
    jurisdictions: tuple[str, ...] = ()  # empty = no jurisdiction filter
    allow_archives: bool = False
    web_search: str = "block"  # block | allow (what the Claude Code hook does with WebSearch)
    changelog: list[dict[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    source_path: str = ""

    @property
    def allows(self) -> list[Rule]:
        return [r for r in self.rules if r.effect == "allow"]

    @property
    def denies(self) -> list[Rule]:
        return [r for r in self.rules if r.effect == "deny"]

    def active(self, rule: Rule) -> bool:
        """An allow rule tagged with a jurisdiction only counts when that jurisdiction is switched on."""
        return not (self.jurisdictions and rule.jurisdiction and rule.jurisdiction not in self.jurisdictions)

    def allowed_summary(self, limit: int = 8) -> list[str]:
        out = [r.describe() for r in self.allows if self.active(r)]
        return out[:limit] + ([f"... and {len(out) - limit} more"] if len(out) > limit else [])


def _check_keys(table: dict[str, Any], allowed: set[str], where: str, errors: list[str]) -> None:
    for k in table:
        if k not in allowed:
            errors.append(f"{where}: unknown key {k!r} (allowed: {', '.join(sorted(allowed))})")


def _text(table: dict[str, Any], key: str, where: str, errors: list[str], limit: int = NOTE_MAX) -> str:
    v = table.get(key, "")
    if not isinstance(v, str):
        errors.append(f"{where}.{key}: expected text")
        return ""
    if len(v) > limit:
        errors.append(f"{where}.{key}: longer than {limit} characters")
    if any(ord(c) < 32 and c not in "\n\t" for c in v):
        errors.append(f"{where}.{key}: control characters are not allowed")
    return v


def _parse_rule(table: Any, effect: str, index: int, errors: list[str]) -> Rule | None:
    where = f"[[{effect}]] #{index + 1}"
    if not isinstance(table, dict):
        errors.append(f"{where}: expected a table")
        return None
    rid = table.get("id")
    if not isinstance(rid, str) or not ID_RE.match(rid):
        errors.append(f"{where}: 'id' is required: 1-40 letters, digits, '_', '.', '-' (got {rid!r})")
        rid = f"#{index + 1}"
    else:
        where = f"[[{effect}]] {rid!r}"
    _check_keys(table, _RULE_KEYS, where, errors)
    kinds = [k for k in ("host", "prefix", "docset") if k in table]
    if len(kinds) != 1:
        errors.append(f"{where}: give exactly one of host / prefix / docset (found {kinds or 'none'})")
        return None
    note = _text(table, "note", where, errors)
    jur = table.get("jurisdiction", "")
    if jur and (not isinstance(jur, str) or not JUR_RE.match(jur)):
        errors.append(f"{where}.jurisdiction: expected a short tag such as 'SE' or 'EU' (got {jur!r})")
        jur = ""
    for flag in ("subdomains", "allow_http"):
        if flag in table and not isinstance(table[flag], bool):
            errors.append(f"{where}.{flag}: expected true or false")
    common = dict(id=rid, effect=effect, jurisdiction=jur, note=note, allow_http=table.get("allow_http") is True)
    kind = kinds[0]
    if kind == "host":
        try:
            host = canonical_host(str(table["host"]))
        except UrlRejected as exc:
            errors.append(f"{where}.host: {exc.detail or exc.code} (got {table['host']!r})")
            return None
        if "." not in host:
            errors.append(f"{where}.host: {host!r} has no dot; give a full domain such as example.org")
        canon = table.get("canonical", "")
        if canon:
            try:
                canon = canonical_host(str(canon))
            except UrlRejected:
                errors.append(f"{where}.canonical: not a valid host")
                canon = ""
        return Rule(kind="domain", host=host, subdomains=table.get("subdomains") is True, canonical=canon, **common)
    if kind == "prefix":
        try:
            c = canonicalize(str(table["prefix"]))
        except UrlRejected as exc:
            errors.append(f"{where}.prefix: {exc.detail or exc.code} (got {table['prefix']!r})")
            return None
        if c.kind != "web" or c.query or c.wrapper:
            errors.append(f"{where}.prefix: must be a plain http(s) URL without a query string, not an archive or redirect URL")
            return None
        return Rule(kind="url_prefix", host=c.host, prefix_path=c.path.rstrip("/"), prefix_scheme=c.scheme, **common)
    ds = table["docset"]
    if not isinstance(ds, str) or not ID_RE.match(ds):
        errors.append(f"{where}.docset: expected a document-set id")
        return None
    return Rule(kind="docset", docset=ds, **common)


def _parse_docset(table: Any, base: Path, index: int, errors: list[str]) -> DocSet | None:
    where = f"[[docset]] #{index + 1}"
    if not isinstance(table, dict):
        errors.append(f"{where}: expected a table")
        return None
    did = table.get("id")
    if not isinstance(did, str) or not ID_RE.match(did):
        errors.append(f"{where}: 'id' is required (1-40 letters, digits, '_', '.', '-')")
        return None
    where = f"[[docset]] {did!r}"
    _check_keys(table, _DOCSET_KEYS, where, errors)
    _text(table, "note", where, errors)
    root = table.get("root")
    if not isinstance(root, str) or not root:
        errors.append(f"{where}.root: required (a folder, relative to the policy file)")
        return None
    files = table.get("files", {})
    if not isinstance(files, dict) or not files:
        errors.append(f"{where}.files: a table of 'relative/path' = 'sha256' is required (create it with: python -m jev_sources hash <folder>)")
        return None
    clean: dict[str, str] = {}
    for rel, digest in files.items():
        if not rel or rel.startswith("/") or "\\" in rel or ".." in rel.split("/"):
            errors.append(f"{where}.files: bad path {rel!r} (relative, forward slashes, no '..')")
        elif not isinstance(digest, str) or not SHA_RE.match(digest.lower()):
            errors.append(f"{where}.files[{rel!r}]: not a sha256 hex digest (64 hex characters)")
        else:
            clean[rel] = digest.lower()
    return DocSet(did, (base / root).resolve(), clean)


def _overlap_warnings(policy: Policy) -> list[str]:
    out: list[str] = []

    def overlaps(a: Rule, b: Rule) -> bool:  # can some URL match both rules?
        if a.kind == "docset" or b.kind == "docset":
            return a.kind == b.kind and a.docset == b.docset
        host_hit = a.host == b.host or (a.subdomains and b.host.endswith("." + a.host)) or (b.subdomains and a.host.endswith("." + b.host))
        if not host_hit:
            return False
        ap, bp = (a.prefix_path if a.kind == "url_prefix" else ""), (b.prefix_path if b.kind == "url_prefix" else "")
        return ap == bp or bp.startswith(ap + "/") or ap.startswith(bp + "/") or not ap or not bp

    for d in policy.denies:
        for a in policy.allows:
            if overlaps(a, d):
                out.append(f"overlap: allow {a.id!r} ({a.describe()}) and deny {d.id!r} ({d.describe()}) both match some URLs; deny wins")
    seen: dict[tuple, str] = {}
    for a in policy.allows:
        key = (a.kind, a.host, a.subdomains, a.prefix_path, a.docset, a.jurisdiction)
        if key in seen:
            out.append(f"duplicate: allow {a.id!r} repeats {seen[key]!r}")
        seen.setdefault(key, a.id)
    used = {r.docset for r in policy.allows if r.kind == "docset"}
    out += [f"docset {d!r} is defined but no allow rule uses it, so nothing in it can be cited" for d in policy.docsets if d not in used]
    return out


def parse_policy(data: Any, base: Path | None = None, source_path: str = "") -> Policy:
    errors: list[str] = []
    base = base or Path.cwd()
    if not isinstance(data, dict):
        raise PolicyError(["top level must be a TOML table"])
    for k in data:
        if k not in ("policy", "changelog", "allow", "deny", "docset"):
            errors.append(f"unknown top-level section {k!r} (allowed: policy, changelog, allow, deny, docset)")
    head = data.get("policy")
    if not isinstance(head, dict):
        raise PolicyError(errors + ["missing [policy] section with name and version"])
    _check_keys(head, _POLICY_KEYS, "[policy]", errors)
    name = _text(head, "name", "[policy]", errors, 80)
    if not name:
        errors.append("[policy].name: required")
    version = head.get("version")
    if not isinstance(version, str) or not VERSION_RE.match(version):
        errors.append(f"[policy].version: required, like '1.0.0' (got {version!r})")
        version = "0.0.0"
    juris = head.get("jurisdictions", [])
    if not isinstance(juris, list) or not all(isinstance(j, str) and JUR_RE.match(j) for j in juris):
        errors.append("[policy].jurisdictions: expected a list of tags such as ['SE', 'EU']")
        juris = []
    web_search = head.get("web_search", "block")
    if web_search not in ("block", "allow"):
        errors.append("[policy].web_search: 'block' or 'allow'")
        web_search = "block"
    if "allow_archives" in head and not isinstance(head["allow_archives"], bool):
        errors.append("[policy].allow_archives: expected true or false")
    log = data.get("changelog", [])
    entries: list[dict[str, str]] = []
    if not isinstance(log, list):
        errors.append("[[changelog]]: expected a list of entries")
        log = []
    for i, e in enumerate(log):
        w = f"[[changelog]] #{i + 1}"
        if not isinstance(e, dict):
            errors.append(f"{w}: expected a table")
            continue
        _check_keys(e, _CHANGELOG_KEYS, w, errors)
        if not VERSION_RE.match(str(e.get("version", ""))) or not DATE_RE.match(str(e.get("date", ""))):
            errors.append(f"{w}: needs version = 'x.y.z' and date = 'YYYY-MM-DD'")
            continue
        entries.append({"version": e["version"], "date": e["date"], "note": _text(e, "note", w, errors)})
    if version != "0.0.0" and not any(e["version"] == version for e in entries):
        errors.append(f"[[changelog]]: no entry for the current version {version}; every change to the policy needs a changelog line")
    rules: list[Rule] = []
    ids: set[str] = set()
    for effect in ("allow", "deny"):
        items = data.get(effect, [])
        if not isinstance(items, list):
            errors.append(f"[[{effect}]]: expected a list of tables")
            continue
        for i, t in enumerate(items):
            r = _parse_rule(t, effect, i, errors)
            if r:
                if r.id in ids:
                    errors.append(f"[[{effect}]] {r.id!r}: duplicate id (ids are unique across allow and deny)")
                ids.add(r.id)
                rules.append(r)
    docsets: dict[str, DocSet] = {}
    raw_docsets = data.get("docset", [])
    if not isinstance(raw_docsets, list):
        errors.append("[[docset]]: expected a list of tables")
        raw_docsets = []
    for i, t in enumerate(raw_docsets):
        ds = _parse_docset(t, base, i, errors)
        if ds:
            if ds.id in docsets:
                errors.append(f"[[docset]] {ds.id!r}: duplicate id")
            docsets[ds.id] = ds
    for r in rules:
        if r.kind == "docset" and r.docset not in docsets:
            errors.append(f"[[{r.effect}]] {r.id!r}: refers to docset {r.docset!r}, which has no [[docset]] section")
    if not errors and not any(r.effect == "allow" for r in rules):
        errors.append("no [[allow]] rules: with default-deny nothing could ever be cited; add at least one")
    if errors:
        raise PolicyError(errors)
    policy = Policy(name=name, version=version, rules=rules, docsets=docsets, jurisdictions=tuple(juris),
                    allow_archives=head.get("allow_archives") is True, web_search=web_search, changelog=entries,
                    source_path=source_path)
    policy.warnings = _overlap_warnings(policy)
    return policy


def load_policy(path: str | Path) -> Policy:
    p = Path(path)
    try:
        raw = p.read_bytes()
    except OSError as exc:
        raise PolicyError([f"cannot read {p}: {exc}"]) from exc
    try:
        data = tomllib.loads(raw.decode("utf-8-sig"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise PolicyError([f"not valid TOML: {exc}"]) from exc
    return parse_policy(data, p.resolve().parent, str(p))
