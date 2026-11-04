"""GuardedFetcher: the policy is applied before connecting and on every redirect hop (fake web, no network)."""

import copy

from jev_sources.guarded import FakeWeb
from jev_sources.policy import parse_policy

BASE = {
    "policy": {"name": "t", "version": "1.0.0"},
    "changelog": [{"version": "1.0.0", "date": "2026-11-03", "note": "x"}],
    "allow": [{"id": "law", "host": "lagen.example", "subdomains": True}, {"id": "gov", "prefix": "https://gov.example/law"}],
    "deny": [],
}
PAGE = "<html><body><p>The notice period is three months.</p></body></html>"


def setup(pages, **over):
    d = copy.deepcopy(BASE)
    d.update(over)
    pol = parse_policy(d)
    web = FakeWeb(pages)
    return pol, web, web.fetcher(pol)


def test_allowed_page_is_read():
    _, web, f = setup({"https://lagen.example/a": PAGE})
    r = f.fetch("https://lagen.example/a")
    assert r.ok and "three months" in r.text and web.contacted == ["https://lagen.example/a"]


def test_forbidden_url_is_never_contacted_or_resolved():
    _, web, f = setup({"https://evil.example/a": PAGE})
    r = f.fetch("https://evil.example/a")
    assert not r.ok and r.status == "policy_blocked" and "builtin/default-deny" in r.detail
    assert web.contacted == [] and web.resolved == []


def test_redirect_from_approved_to_forbidden_is_stopped_before_contacting_it():
    _, web, f = setup({"https://lagen.example/old": ("redirect", "https://evil.example/new"), "https://evil.example/new": PAGE})
    r = f.fetch("https://lagen.example/old")
    assert r.status == "policy_blocked" and "evil.example" in r.detail
    assert web.contacted == ["https://lagen.example/old"] and "evil.example" not in web.resolved
    assert f.decision_for("https://lagen.example/old").rule_id == "builtin/default-deny"


def test_redirect_to_other_path_on_prefix_host_is_checked_by_path():
    _, web, f = setup({"https://gov.example/law/a": ("redirect", "https://gov.example/private"), "https://gov.example/private": PAGE})
    r = f.fetch("https://gov.example/law/a")
    assert r.status == "policy_blocked" and web.contacted == ["https://gov.example/law/a"]


def test_redirect_to_another_approved_page_is_fine():
    _, web, f = setup({"https://lagen.example/old": ("redirect", "https://www.lagen.example/new"), "https://www.lagen.example/new": PAGE})
    assert f.fetch("https://lagen.example/old").ok


def test_redirect_chain_two_hops_second_forbidden():
    _, web, f = setup({"https://lagen.example/a": ("redirect", "https://lagen.example/b"),
                       "https://lagen.example/b": ("redirect", "https://elsewhere.example/c")})
    r = f.fetch("https://lagen.example/a")
    assert r.status == "policy_blocked" and "elsewhere.example" not in web.resolved


def test_open_redirector_url_is_rejected_before_any_connection():
    _, web, f = setup({"https://lagen.example/r?url=https://evil.example/": PAGE})
    r = f.fetch("https://lagen.example/r?url=https://evil.example/")
    assert r.status == "policy_blocked" and web.contacted == []


def test_cached_chain_is_rechecked_after_policy_change(tmp_path):
    pages = {"https://lagen.example/old": ("redirect", "https://other.example/x"), "https://other.example/x": PAGE}
    loose = copy.deepcopy(BASE)
    loose["allow"].append({"id": "other", "host": "other.example"})
    web = FakeWeb(pages)
    f1 = web.fetcher(parse_policy(loose))
    f1.cache_dir = None
    from jev_sources.guarded import GuardedFetcher

    g1 = GuardedFetcher(parse_policy(loose), cache_dir=tmp_path, transport=web.transport, resolver=web.resolver, per_host_delay=0)
    assert g1.fetch("https://lagen.example/old").ok
    g2 = GuardedFetcher(parse_policy(BASE), cache_dir=tmp_path, transport=web.transport, resolver=web.resolver, per_host_delay=0)
    r = g2.fetch("https://lagen.example/old")  # served from the cache, but the chain is judged again
    assert r.status == "policy_blocked" and "other.example" in r.detail


def test_archive_url_blocked_by_default_and_allowed_when_policy_says_so():
    url = "https://web.archive.org/web/2020/https://lagen.example/a"
    _, web, f = setup({url: PAGE})
    assert f.fetch(url).status == "policy_blocked" and web.contacted == []
    _, web2, f2 = setup({url: PAGE}, policy={**BASE["policy"], "allow_archives": True})
    assert f2.fetch(url).ok


def test_docset_reference_reads_local_file(tmp_path):
    import hashlib

    root = tmp_path / "d"
    root.mkdir()
    (root / "a.md").write_text("Leave is 25 days.", encoding="utf-8")
    d = copy.deepcopy(BASE)
    d["allow"].append({"id": "hr", "docset": "hr"})
    d["docset"] = [{"id": "hr", "root": "d", "files": {"a.md": hashlib.sha256(b"Leave is 25 days.").hexdigest()}}]
    pol = parse_policy(d, tmp_path)
    f = FakeWeb({}).fetcher(pol)
    r = f.fetch("docset:hr/a.md")
    assert r.ok and "25 days" in r.text
    (root / "a.md").write_text("Leave is 30 days.", encoding="utf-8")
    r = f.fetch("docset:hr/a.md")
    assert r.status == "policy_blocked" and "docset_modified" in f.decision_for("docset:hr/a.md").code
