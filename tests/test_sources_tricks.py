"""URL trick list, the explain/init commands and public-suffix awareness.

TRICKS was written as a held-out list: the cases were probed against the engine first, the failures were fixed, and
every case stays here as a regression test. Each row: (url, expected) where expected is "allow" or the rule id /
code that must reject it. Hosts use the reserved .example/.test names; none of them is real.
"""

import copy

import pytest

from jev_sources.__main__ import main
from jev_sources.engine import evaluate
from jev_sources.explain import explain
from jev_sources.policy import PolicyError, load_policy, parse_policy

BASE = {
    "policy": {"name": "tricks", "version": "1.0.0"},
    "changelog": [{"version": "1.0.0", "date": "2026-11-04"}],
    "allow": [
        {"id": "a", "host": "lagen.example", "subdomains": True},
        {"id": "b", "prefix": "https://gov.example/law"},
        {"id": "c", "host": "xn--strae-oqa.example"},
    ],
    "deny": [{"id": "d", "prefix": "https://lagen.example/private"}],
}
POLICY = parse_policy(BASE)

TRICKS = [
    # ports: the port must be the scheme's own default
    ("https://lagen.example:443/x", "allow"),
    ("https://lagen.example:/x", "allow"),
    ("https://lagen.example:0/x", "url_bad_port"),
    ("https://lagen.example:80/x", "port"),
    ("https://lagen.example:8443/x", "port"),
    ("https://lagen.example:99999/x", "url_malformed_url"),
    ("http://lagen.example:443/x", "port"),
    # hosts
    ("https://LAGEN.Example./x", "allow"),
    ("https://lagen.example../x", "url_malformed_host"),
    ("https://.lagen.example/x", "url_malformed_host"),
    ("https://a..lagen.example/x", "url_malformed_host"),
    ("https://lagen.example.evil.test/x", "builtin/default-deny"),
    ("https://xlagen.example/x", "builtin/default-deny"),
    ("https://lagen.example%2eevil.test/", "url_malformed_host"),
    ("https://%6cagen.example/", "url_malformed_host"),
    ("https://lagen.example。/x", "url_ambiguous_idna_host"),
    ("https://lаgen.example/", "builtin/default-deny"),  # Cyrillic a
    ("https://strasse.example/", "builtin/default-deny"),  # the host the policy does NOT name
    ("https://straße.example/", "url_ambiguous_idna_host"),  # IDNA 2003 would turn this into strasse.example
    ("https://xn--strae-oqa.example/", "allow"),
    ("https://①.example/", "url_ambiguous_idna_host"),
    # userinfo and delimiters
    ("https://lagen.example@evil.test/", "url_userinfo_in_url"),
    ("https://lagen.example:80@evil.test/", "url_userinfo_in_url"),
    ("https://evil.test#@lagen.example/", "builtin/default-deny"),
    ("https://evil.test?@lagen.example/", "builtin/default-deny"),
    ("https://lagen.example\t/x", "url_bad_characters"),
    ("https:/\\evil.test", "url_backslash"),
    ("https:lagen.example/x", "url_no_host"),
    # paths: allow boundary
    ("https://gov.example/law", "allow"),
    ("https://gov.example/law/", "allow"),
    ("https://gov.example/law/a/b", "allow"),
    ("https://gov.example//law/x", "allow"),
    ("https://gov.example/lawyer", "builtin/default-deny"),
    ("https://gov.example/law2/x", "builtin/default-deny"),
    ("https://gov.example/LAW/x", "builtin/default-deny"),
    ("https://gov.example/law/../x", "builtin/default-deny"),
    ("https://gov.example/law/%2e%2e/x", "builtin/default-deny"),
    ("https://gov.example/law/%252e%252e/x", "builtin/default-deny"),
    ("https://gov.example/law/..%2fx", "url_encoded_slash"),
    ("https://gov.example/law%2fx", "url_encoded_slash"),
    ("https://gov.example/law;x/y", "builtin/default-deny"),
    # paths: deny boundary (case, dot segments, encodings, path parameters, NUL)
    ("https://lagen.example/private", "d"),
    ("https://lagen.example/private/x", "d"),
    ("https://lagen.example/PRIVATE/x", "d"),
    ("https://lagen.example/%70rivate", "d"),
    ("https://lagen.example/./private", "d"),
    ("https://lagen.example//private/x", "d"),
    ("https://lagen.example/a/../private/x", "d"),
    ("https://lagen.example/x/%252e%252e/private", "d"),
    ("https://lagen.example/private;jsessionid=1", "d"),
    ("https://lagen.example/private;a/b;c/d", "d"),
    ("https://lagen.example/private%00", "url_bad_characters"),
    ("https://lagen.example/private%2fx", "url_encoded_slash"),
    ("https://lagen.example/privately", "allow"),
    ("https://lagen.example/x#/private", "allow"),
    # query strings that carry another URL
    ("https://lagen.example/x?u=https://evil.test/", "builtin/default-deny"),
    ("https://lagen.example/x?next=https%3A%2F%2Fevil.test", "builtin/default-deny"),
    ("https://lagen.example/x?a=b&r=HTTP://evil.test", "builtin/default-deny"),
    ("https://lagen.example/x?u=//evil.test", "builtin/default-deny"),
    ("https://lagen.example/x?u=https://gov.example/law/a", "allow"),
    ("https://lagen.example/x#https://evil.test", "allow"),
    # schemes and numeric hosts
    ("HTTPS://lagen.example/x", "allow"),
    ("ftp://lagen.example/x", "url_bad_scheme"),
    ("javascript:alert(1)", "url_bad_scheme"),
    ("//lagen.example/x", "url_no_scheme"),
    ("https://2130706433/", "url_ip_literal_host"),
    ("https://0x7f.1/", "url_ip_literal_host"),
    ("https://[::1]/", "url_ip_literal_host"),
    ("https://[::ffff:1.2.3.4]/", "url_ip_literal_host"),
    # wrappers
    ("https://web.archive.org/web/2020/https://lagen.example/x", "builtin/wrapper"),
    ("https://translate.google.com/translate?u=https://lagen.example/x", "builtin/wrapper"),
]


@pytest.mark.parametrize("url,expected", TRICKS)
def test_trick(url, expected):
    d = evaluate(POLICY, url)
    if expected == "allow":
        assert d.allowed, (url, d.message)
    else:
        assert not d.allowed, url
        assert expected in (d.code, d.rule_id), (url, d.code, d.rule_id)
        assert d.rule_id in d.message  # every rejection names its rule


# ---- public suffixes ---------------------------------------------------------------------------------


def with_allow(**rule):
    d = copy.deepcopy(BASE)
    d["allow"].append({"id": "x", **rule})
    return parse_policy(d)


def test_subdomains_on_a_multi_tenant_suffix_is_refused():
    with pytest.raises(PolicyError, match="unrelated people"):
        with_allow(host="github.io", subdomains=True)
    assert with_allow(host="someone.github.io")  # one named tenant is fine


def test_public_suffix_and_user_content_hosts_warn():
    assert any("public suffix" in w for w in with_allow(host="co.uk", subdomains=True).warnings)
    assert any("public suffix" in w for w in with_allow(host="com.au").warnings)
    assert any("anyone can publish" in w for w in with_allow(host="github.com").warnings)
    assert not any("anyone can publish" in w for w in with_allow(prefix="https://github.com/example-org").warnings)
    assert not any("public suffix" in w for w in with_allow(host="legislation.gov.uk").warnings)


def test_carve_out_is_labelled_not_a_conflict():
    p = parse_policy({**BASE, "deny": [{"id": "d2", "prefix": "https://gov.example/law/secret"}]})
    assert any("carve-out" in w and "d2" in w for w in p.warnings)


# ---- explain and init --------------------------------------------------------------------------------


def test_explain_shows_canonical_form_rules_and_decision():
    text = explain(POLICY, "https://LAGEN.example./Private/x")
    assert "Canonical:  https://lagen.example/Private/x" in text
    assert "MATCH    deny  d" in text and "REJECTED by d" in text


def test_explain_for_unparseable_url_and_wrong_path():
    assert "userinfo_in_url" in explain(POLICY, "https://lagen.example@evil.test/")
    assert "under none of them" in explain(POLICY, "https://gov.example/other")


@pytest.mark.parametrize("template", ["docs-only", "gov-sources"])
def test_templates_are_valid(tmp_path, template, capsys):
    out = tmp_path / "p.toml"
    assert main(["init", template, "--out", str(out)]) == 0
    p = load_policy(out)
    assert p.allows
    assert main(["init", template, "--out", str(out)]) == 2  # does not overwrite
    assert main(["validate", "--policy", str(out)]) == 0
    assert not [w for w in p.warnings if "public suffix" in w or "anyone can publish" in w]


def test_offline_corpus_template_pins_the_folder(tmp_path):
    docs = tmp_path / "notes"
    docs.mkdir()
    (docs / "a.md").write_text("Leave is 25 days.", encoding="utf-8")
    out = tmp_path / "pol" / "p.toml"
    assert main(["init", "offline-corpus", "--out", str(out), "--docs", str(docs)]) == 0
    p = load_policy(out)
    assert evaluate(p, "docset:corpus/a.md").allowed
    (docs / "a.md").write_text("Leave is 30 days.", encoding="utf-8")
    assert evaluate(p, "docset:corpus/a.md").code == "docset_modified"
    assert main(["init", "offline-corpus", "--out", str(tmp_path / "q.toml")]) == 2  # needs --docs
    assert main(["init", "nope", "--out", str(tmp_path / "r.toml")]) == 2


def test_explain_command_runs(tmp_path, capsys):
    out = tmp_path / "p.toml"
    main(["init", "docs-only", "--out", str(out)])
    assert main(["explain", "https://docs.python.org/3/library/json.html", "--policy", str(out)]) == 0
    assert "ALLOWED by python-docs" in capsys.readouterr().out
