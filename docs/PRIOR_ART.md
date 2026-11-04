# Prior art (round 2, read 2026-11-04)

What was actually fetched, and what it changed here.

## Public Suffix List
Sources: publicsuffix.org/list, the format page on the project wiki, the list file itself.
* Maintained on GitHub; the website copy is refreshed daily; the list changes a few times per week; consumers should download at most once a day. The page shows (c) Mozilla Foundation; the file header states MPL-2.0.
* Two sections: ICANN (registry-delegated, e.g. `gov.uk`, `co.jp`, `gov`) and PRIVATE (submitted by domain holders, e.g. hosting platforms). Rules: plain suffix, `*.x` wildcard (one whole leftmost label), `!a.x` exception that beats everything. Algorithm: longest matching rule, exception wins (and its leftmost label is dropped), default rule `*`; registrable domain = suffix + one label.
* Applied: `tools/update_suffixes.py` keeps the ICANN section only (6,948 rules, 77 KB, IDN labels as punycode), with source, list version/commit, generation date and the MPL-2.0 notice in the file header (`src/jev_sources/data/public_suffix_icann.dat`). The PSL algorithm is implemented in `suffixes.py`. PRIVATE (about 5,300 lines) is not bundled: size, weekly churn, and a hand-made `MULTI_TENANT` list covers the platforms people actually write policies for. New `suffix = "gov.uk"` rule: explicit, validated against the ICANN list, covers names registered under the suffix but never the suffix, always warns `broad:`.
* Staleness: `validate` prints the snapshot version; refresh before a release. The snapshot is used only when a policy is written (and by `suffix`), never to judge a fetched URL.

## Claude Code permissions and sandbox
Source: code.claude.com/docs/en/permissions.
* `WebFetch(domain:example.com)` matches the hostname, case-insensitive, trailing dot stripped from rule and host; `*.example.com` matches subdomains at any depth but not the apex; a `*` elsewhere matches only text between dots, so `example.*` cannot match `example.evil.com`. Deny rules take priority. The docs warn that WebFetch rules do not stop Bash `curl`/`wget`; they point to the sandbox network allowlist for enforcement that does not depend on command text.
* Compared: ours matches the apex with `subdomains = true` (stated in the rule text), strips one trailing dot, never uses mid-host wildcards, and adds URL-path prefixes, which WebFetch domain rules lack. The "hook sees tool calls only" limit in SECURITY.md is the same gap; recommended pairing is this hook plus the sandbox network allowlist.

## CSP source lists
Source: MDN, Content-Security-Policy.
* Host-sources: scheme/port/path optional, `*.example.com` subdomains only, a path ending in `/` is a prefix, otherwise exact match; `http://x` also allows `https://x`.
* Compared: our `prefix` matches whole path segments (like the trailing-slash form), `https` only unless `allow_http` (CSP's silent upgrade is the opposite direction and is not copied). The page says nothing on redirects; from memory (not fetched), CSP3 ignores the path of a redirect target when matching, which is the reason we judge every hop's full URL instead.

## Cedar and OPA
Source: search results on Cedar docs (AWS), not primary spec text; OPA conflict resolution was not found in them.
* Cedar: default deny; any matching `forbid` beats any `permit`; policies are independent and order-free; deliberately not Turing-complete so they can be analysed. Our rules: default deny, deny beats allow, order-independent, data-only TOML, `validate` reports overlaps statically. Idea kept: a decision must be explainable (`explain`).

## WHATWG URL Standard
Source: url.spec.whatwg.org (first 100k of ~189k characters read; path/query states not read).
* Leading/trailing C0 controls and spaces stripped; tab and newline removed anywhere; `\` is `/` for special schemes; missing or extra slashes tolerated (`https:example.org`); `@` handling re-encodes earlier `@`; host: percent-decode then UTS #46 domain-to-ASCII, forbidden host code points fail; IPv4 in decimal/octal/hex with fewer than four parts; IPv6 zone ids are NOT supported (the `%` fails); default ports become null.
* Applied: outer whitespace accepted (spec strips it), inner tab/newline/backslash rejected (we refuse to guess), extra slashes rejected (`no_host`), zone ids rejected, all IP/numeric forms rejected, ports must be the scheme default.

## IDNA: UTS #46 vs IDNA2008
Source: unicode.org/reports/tr46.
* Transitional processing (deprecated) maps `ß` to `ss`; nontransitional keeps it and is described as compatible with IDNA2008. U+3002, U+FF0E, U+FF61 are label separators mapped to `.`. UTS #46 does not solve confusables; UTS #39 (mixed-script, restriction levels) does.
* Applied: Python's codec is IDNA 2003 (transitional-like), so any host that does not survive an encode/decode round trip is rejected (`ambiguous_idna_host`); fullwidth dots and letters therefore reject. Not done: UTS #39 mixed-script detection (a Cyrillic lookalike is rejected only because it is not on the allowlist, and flagged as a possible lookalike in the message). Soft hyphen and zero-width characters, which UTS #46 drops, are rejected outright.

## Not researched this round
Sandbox network-allowlist page (only referenced from the permissions page), UTS #39 itself, OPA documentation.
