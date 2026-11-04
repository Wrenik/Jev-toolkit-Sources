"""Round 2 held-out URL tricks. Written BEFORE any code change of round 2 (see docs/ROUND2_HELDOUT.md for the
first-run result); every row stays as a regression test. Expected: "allow", a rule id / code, or "url_*" meaning
"rejected as an unusable URL form, any reason". Hosts are reserved .example/.test names."""

import pytest

from jev_sources.engine import evaluate
from jev_sources.policy import parse_policy

POLICY = parse_policy(
    {
        "policy": {"name": "round2", "version": "1.0.0"},
        "changelog": [{"version": "1.0.0", "date": "2026-11-04"}],
        "allow": [
            {"id": "a", "host": "lagen.example", "subdomains": True},
            {"id": "b", "prefix": "https://gov.example/law"},
        ],
        "deny": [{"id": "d", "prefix": "https://lagen.example/private"}],
    }
)
DEFAULT = "builtin/default-deny"

H = [
    # WHATWG strips leading/trailing C0+space and removes tab/newline anywhere; we accept the first, refuse the second
    (" https://lagen.example/x ", "allow"),
    ("\thttps://lagen.example/x", "allow"),
    ("https://lagen.example/x\n", "allow"),
    ("https://lagen.ex\nample/x", "url_bad_characters"),
    ("htt\tps://lagen.example/", "url_bad_characters"),
    ("https://lagen.example/pri\tvate", "url_bad_characters"),
    ("https://lagen.example/pri\r\nvate", "url_bad_characters"),
    # backslashes and missing/extra slashes (a browser reads \ as / and skips extra slashes)
    ("https://lagen.example\\@evil.test/", "url_backslash"),
    ("https://evil.test\\@lagen.example/", "url_backslash"),
    ("https:\\\\lagen.example\\x", "url_backslash"),
    ("https:///lagen.example/x", "url_*"),
    ("https:////lagen.example/x", "url_*"),
    ("https://lagen.example/x#\\evil", "url_backslash"),
    # percent-encoding: mixed case, overlong, control characters
    ("https://lagen.example/%70%52ivate", "d"),
    ("https://lagen.example/%50rivate/x", "d"),
    ("https://lagen.example/%2E/private", "d"),
    ("https://lagen.example/%2e%2E/private", "d"),
    ("https://lagen.example/x/%2E%2e/private", "d"),
    ("https://lagen.example/private%2F", "url_encoded_slash"),
    ("https://lagen.example/private%5C", "url_encoded_slash"),
    ("https://lagen.example/%C0%AFprivate", "url_*"),
    ("https://lagen.example/%0d%0aSet-Cookie:x", "url_bad_characters"),
    ("https://lagen.example/100%", "allow"),
    ("https://gov.example/law%20x", DEFAULT),
    ("https://gov.example/law∕x", DEFAULT),  # DIVISION SLASH is an ordinary character, not a separator
    # IPv6 zone ids and numeric hosts
    ("https://[fe80::1%25eth0]/", "url_*"),
    ("https://[fe80::1%eth0]/", "url_*"),
    ("https://0300.0250.0.1/", "url_ip_literal_host"),
    ("https://127.1/", "url_ip_literal_host"),
    ("https://1.1.1.1.example/", DEFAULT),
    # userinfo and lookalike hosts
    ("https://lagen.example:443@evil.test/", "url_userinfo_in_url"),
    ("https://lagen.example:8080@lagen.example/", "url_userinfo_in_url"),
    ("https://lagen.example%40evil.test/", "url_*"),
    ("https://lagen.example-evil.test/", DEFAULT),
    ("https://evil.test/lagen.example", DEFAULT),
    ("https://evil.test/?lagen.example", DEFAULT),
    ("https://lagen.example.:443/x", "allow"),
    ("https://LAGEN.EXAMPLE/", "allow"),
    # Unicode dots, width forms, invisible and bidi characters (UTS #46 maps or removes many of these)
    ("https://lagen。example/x", "url_*"),
    ("https://lagen．example/x", "url_*"),
    ("https://lagen｡example/x", "url_*"),
    ("https://ｌａｇｅｎ.example/", "url_*"),
    ("https://lagen.example/‮etavirp", "url_bad_characters"),
    ("https://lagen.example​/x", "url_*"),
    ("https://lagen.exa­mple/x", "url_*"),
    ("https://lagen.example/pri​vate", "url_bad_characters"),
    # schemes
    ("file:///etc/passwd", "url_bad_scheme"),
    ("file://lagen.example/x", "url_bad_scheme"),
    ("data:text/html,<a>", "url_bad_scheme"),
    ("javascript://lagen.example/%0aalert(1)", "url_bad_scheme"),
    ("JaVaScRiPt:alert(1)", "url_bad_scheme"),
    (" javascript:alert(1)", "url_bad_scheme"),
    ("blob:https://lagen.example/uuid", "url_bad_scheme"),
    ("view-source:https://lagen.example/", "url_bad_scheme"),
    ("about:blank", "url_bad_scheme"),
    ("ws://lagen.example/", "url_bad_scheme"),
    ("mailto:a@lagen.example", "url_bad_scheme"),
    # query strings that carry another URL (open redirectors), including encoded forms
    ("https://lagen.example/x?u=%2F%2Fevil.test", DEFAULT),
    ("https://lagen.example/x?u=https:%2F%2Fevil.test", DEFAULT),
    ("https://lagen.example/x?u=%68ttps://evil.test", DEFAULT),
    ("https://lagen.example/x?u=%2568ttps://evil.test", DEFAULT),
    ("https://lagen.example/x?u=https://gov.example/law2", DEFAULT),
    ("https://lagen.example/x?u=data:text/html,x", "allow"),
    ("http://lagen.example/x", "a"),  # https only unless allow_http
]


@pytest.mark.parametrize("url,expected", H)
def test_round2(url, expected):
    d = evaluate(POLICY, url)
    if expected == "allow":
        assert d.allowed, (url, d.message)
    else:
        assert not d.allowed, (url, d.rule_id)
        ok = d.code.startswith("url_") if expected == "url_*" else expected in (d.code, d.rule_id)
        assert ok, (url, d.code, d.rule_id)
        assert d.rule_id in d.message
