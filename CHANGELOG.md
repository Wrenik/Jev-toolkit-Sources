# Changelog

## 0.1.0 (unreleased)

### Round 2

* Bundled Public Suffix List snapshot (ICANN section, 77 KB, MPL-2.0 data file) with the real PSL algorithm; `tools/update_suffixes.py` regenerates it. New `suffix =` rule (e.g. `gov.uk`). `validate` prints the snapshot version.
* 64 new held-out URL tricks (`tests/test_sources_round2.py`, first-run record in `docs/ROUND2_HELDOUT.md`); fixes: bidi/zero-width/format characters in a URL, invalid UTF-8 (overlong `%C0%AF`) in paths, multiply-encoded URLs in query values.
* `hash` skips symlinks that leave the folder; symlink and relative-root docset tests. `report.py` renders `forbidden_source`. End-to-end example (`examples/`, `docs/END_TO_END.md`). `docs/PRIOR_ART.md`, SECURITY.md threat model.

First release. Source restriction with a versioned TOML allowlist policy, enforced before the model sees retrieval results (`filter`, `fetch`, optional Claude Code hook) and after it answers (`check`).

### Added

* Policy file: `[[allow]]` / `[[deny]]` rules by host (optionally with subdomains), path prefix or hash-pinned document set; jurisdiction tags; per-policy changelog that must cover the current version.
* URL canonicalisation before any rule is applied: userinfo, punycode/IDN, case, trailing dot, ports, percent-encoding, dot segments, backslashes, archive/cache/translate wrappers, open-redirector URLs in query strings.
* Guarded fetcher: every redirect hop judged before the connection; forbidden hosts are not contacted.
* `check` (rewrite loop, hard cap 3 rounds), `filter`, `fetch`, `hook` (monitor mode by default), `allow-once`, `hash`, `eval`, `demo`, `prompt`.
* `explain <url>`: step-by-step reasoning for one URL (canonical form, which rules matched and why the others did not, the decision).
* `init <template>`: starter policies `docs-only`, `gov-sources`, `offline-corpus` (the last pins a folder by hash).
* Public-suffix awareness (small built-in list, no network): `subdomains = true` on multi-tenant suffixes such as `github.io` is refused; registry-style suffixes and user-content hosts get warnings. Deny rules nested in an allow rule are reported as a `carve-out` note instead of an alarming overlap.
* 195 offline tests, 46 hand-written scenarios (26 dev, 20 held-out).

### Fixed (found by the pre-release trick list in `tests/test_sources_tricks.py`)

* `https://host:80/` was treated as the default port; the port must now be the scheme's own default. Port `0` is rejected.
* `straße.example` was silently mapped to `strasse.example` (IDNA 2003) so a rule for one approved the other. Names that do not survive an IDNA round trip are rejected as `ambiguous_idna_host`.
* A deny rule on `/private` did not match `/private;jsessionid=1`; deny matching now ignores `;parameters` per segment.
* `%00` in a path decoded to a NUL character and slipped past deny rules; control characters in the decoded path are rejected.
* Several trailing dots on a host (`host..`) were accepted; only one is dropped.
* The "looks similar to the allowed host" hint named the same host when only the path was wrong; it now says the host has approved prefixes but this path is under none.
* `validate` picked the "latest change" by string comparison (`1.9.0` beat `1.10.0`).

### Known limits

See "Known limits" in `docs/SOURCE_RESTRICTION.md`. In short: it checks what a claim cites, it cannot prove the model did not use other knowledge, and the hook sees Claude Code tool calls only.
