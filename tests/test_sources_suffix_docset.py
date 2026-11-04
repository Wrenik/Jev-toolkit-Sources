"""Public Suffix List snapshot, `suffix =` rules, and docset path handling (symlinks, relative roots)."""

import copy
import hashlib
import os

import pytest

from jev_sources.engine import evaluate, sha256_manifest
from jev_sources.guarded import FakeWeb
from jev_sources.policy import PolicyError, load_policy, parse_policy
from jev_sources.suffixes import is_icann_suffix, is_public_suffix, public_suffix, registrable_domain, snapshot_info

BASE = {
    "policy": {"name": "t", "version": "1.0.0"},
    "changelog": [{"version": "1.0.0", "date": "2026-11-04"}],
    "allow": [{"id": "a", "host": "lagen.example"}],
}


def pol(*rules, **extra):
    d = copy.deepcopy(BASE)
    d["allow"] += list(rules)
    d.update(extra)
    return parse_policy(d)


@pytest.mark.parametrize(
    "host,suffix,reg",
    [
        ("co.uk", "co.uk", ""),
        ("legislation.gov.uk", "gov.uk", "legislation.gov.uk"),
        ("a.b.example.co.uk", "co.uk", "example.co.uk"),
        ("foo.ck", "foo.ck", ""),
        ("www.ck", "ck", "www.ck"),  # wildcard *.ck and exception !www.ck
        ("city.kobe.jp", "kobe.jp", "city.kobe.jp"),
        ("example.com", "com", "example.com"),
        ("x.invalidtld", "invalidtld", "x.invalidtld"),
    ],
)
def test_psl_algorithm(host, suffix, reg):
    assert public_suffix(host) == suffix and registrable_domain(host) == reg


def test_snapshot_is_dated_and_compact():
    info = snapshot_info()
    assert info["PSL version"][:4].isdigit() and int(info["Rules"]) > 6000
    from importlib import resources

    assert len(resources.files("jev_sources").joinpath("data/public_suffix_icann.dat").read_bytes()) < 300_000


def test_suffix_rule_covers_everything_under_it_but_not_the_suffix():
    p = pol({"id": "gov", "suffix": "gov.uk"})
    assert evaluate(p, "https://legislation.gov.uk/x").allowed
    assert evaluate(p, "https://a.b.nhs.gov.uk/x").allowed
    assert not evaluate(p, "https://gov.uk/x").allowed
    assert not evaluate(p, "https://gov.uk.evil.test/x").allowed
    assert not evaluate(p, "https://evilgov.uk/x").allowed
    assert any("EVERY domain" in w for w in p.warnings)
    assert "every domain under the registry suffix gov.uk" in p.allows[1].describe()
    assert evaluate(pol({"id": "g", "suffix": "gov"}), "https://www.whitehouse.gov/").allowed


def test_suffix_rule_must_name_a_real_registry_suffix():
    for bad in ("example.com", "github.io", "lagen.example", "uk.co"):
        with pytest.raises(PolicyError, match="suffix"):
            pol({"id": "x", "suffix": bad})
    with pytest.raises(PolicyError, match="subdomains"):
        pol({"id": "x", "suffix": "gov.uk", "subdomains": True})
    with pytest.raises(PolicyError, match="exactly one"):
        pol({"id": "x", "suffix": "gov.uk", "host": "a.example"})


def test_deny_suffix_beats_allow_and_old_warning_points_to_suffix():
    p = pol({"id": "gov", "suffix": "gov.uk"}, **{"deny": [{"id": "nodef", "host": "mod.gov.uk", "subdomains": True}]})
    assert evaluate(p, "https://mod.gov.uk/x").rule_id == "nodef"
    w = pol({"id": "co", "host": "co.uk", "subdomains": True}).warnings
    assert any("write suffix = 'co.uk'" in x for x in w)
    assert is_public_suffix("com.au") and is_icann_suffix("gov") and not is_icann_suffix("example.com")


def test_redirect_from_suffix_site_to_off_policy_host_is_stopped():
    p = pol({"id": "gov", "suffix": "gov.uk"})
    web = FakeWeb(
        {
            "https://legislation.gov.uk/a": ("redirect", "https://gov.uk.evil.test/b"),
            "https://gov.uk.evil.test/b": "<p>x</p>",
        }
    )
    r = web.fetcher(p).fetch("https://legislation.gov.uk/a")
    assert r.status == "policy_blocked"
    assert not any("evil.test" in u for u in web.contacted) and "gov.uk.evil.test" not in web.resolved


# ---- docset paths ------------------------------------------------------------------------------------


def _docset_policy(tmp_path, root_text, folder):
    sha = hashlib.sha256(b"Leave is 25 days.").hexdigest()
    toml = (
        f'[policy]\nname = "d"\nversion = "1.0.0"\n[[changelog]]\nversion = "1.0.0"\ndate = "2026-11-04"\n'
        f'[[allow]]\nid = "hr"\ndocset = "hr"\n[[docset]]\nid = "hr"\nroot = "{root_text}"\nfiles = {{ "a.md" = "{sha}" }}\n'
    )
    pf = tmp_path / "pol" / "p.toml"
    pf.parent.mkdir(exist_ok=True)
    pf.write_text(toml, encoding="utf-8")
    (folder / "a.md").write_text("Leave is 25 days.", encoding="utf-8")
    return load_policy(pf)


def test_relative_root_is_relative_to_the_policy_file_not_the_working_directory(tmp_path, monkeypatch):
    docs = tmp_path / "docs"
    docs.mkdir()
    p = _docset_policy(tmp_path, "../docs", docs)
    other = tmp_path / "elsewhere"
    other.mkdir()
    monkeypatch.chdir(other)
    assert evaluate(p, "docset:hr/a.md").allowed
    for ref in (
        "docset:hr/../p.toml",
        "docset:hr/./a.md",
        "docset:hr//a.md",
        "docset:hr/a.md%2e",
        "docset:hr/%2e%2e/a.md",
    ):
        assert not evaluate(p, ref).allowed, ref


def _symlink(link, target, is_dir=False):
    try:
        os.symlink(target, link, target_is_directory=is_dir)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")


def test_symlinked_file_leaving_the_folder_is_refused_even_with_the_right_hash(tmp_path):
    docs = tmp_path / "docs"
    docs.mkdir()
    outside = tmp_path / "secret.md"
    outside.write_text("Leave is 25 days.", encoding="utf-8")  # same bytes, so the hash matches
    p = _docset_policy(tmp_path, "../docs", docs)
    (docs / "a.md").unlink()
    _symlink(docs / "a.md", outside)
    d = evaluate(p, "docset:hr/a.md")
    assert not d.allowed and d.code == "docset_file_missing"
    assert "a.md" not in sha256_manifest(docs)  # `hash` does not list a link that leaves the folder


def test_symlinked_folder_inside_the_docset_is_refused_and_a_symlinked_root_is_resolved(tmp_path):
    docs = tmp_path / "docs"
    docs.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    (out / "b.md").write_text("x", encoding="utf-8")
    _symlink(docs / "sub", out, True)
    sha = hashlib.sha256(b"x").hexdigest()
    p = _docset_policy(tmp_path, "../docs", docs)
    p.docsets["hr"].files["sub/b.md"] = sha
    assert evaluate(p, "docset:hr/sub/b.md").code == "docset_file_missing"
    real = tmp_path / "real"
    real.mkdir()
    _symlink(tmp_path / "linkroot", real, True)
    p2 = _docset_policy(tmp_path, "../linkroot", real)
    assert evaluate(p2, "docset:hr/a.md").allowed  # a root that IS a link is the folder the policy author chose


def test_end_to_end_example_names_the_rule_in_the_html_report(tmp_path):
    import runpy
    from pathlib import Path

    script = Path(__file__).resolve().parent.parent / "examples" / "end_to_end.py"
    if not script.exists():
        pytest.skip("examples/ not in this checkout")
    out = tmp_path / "r.html"
    ns = runpy.run_path(str(script))
    assert ns["main"](str(out)) == 0
    html = out.read_text(encoding="utf-8")
    assert "no-forums" in html and "not approved by the policy" in html and "<script" not in html
