# jev-toolkit-sources v0.1.0

An experimental learning project: restrict an answer to sources on a policy you write (a plain TOML file), enforced before the model sees retrieval results and after it answers, with the rule named in every rejection.

## What you get

* A policy format with allow/deny rules for hosts, path prefixes and hash-pinned local document sets, jurisdiction tags and a mandatory changelog.
* A URL engine that canonicalises before matching (userinfo, IDN/punycode, ports, encodings, dot segments, archive/redirect wrappers) and rejects what it cannot judge, with a stable code.
* Commands: `init`, `validate`, `explain`, `fetch`, `filter`, `check`, `hook`, `allow-once`, `hash`, `eval`, `demo`, `prompt`.
* Three starter policies: documentation only, government sources, offline corpus.
* 195 offline tests; no API key or network needed to try it (`python -m jev_sources demo`).

## What it does not do (please read)

* It checks what each claim **cites**. It **cannot prove the model did not use other knowledge**; a claim without a source is flagged `untraceable`, never approved.
* The Claude Code hook sees WebFetch/WebSearch calls only, not Bash/curl or model memory, and starts in monitor mode. An egress firewall is the real boundary.
* A domain on the allowlist is trusted as a whole unless you use path prefixes. Public-suffix awareness is a small built-in list, not the full Public Suffix List.
* The evaluation scenarios (46) were written by the author of the code. They are not evidence of real-world accuracy; the first held-out run was 18/20 before any fix.
* The optional judge sends redacted claim/quote/passage text to TypeSafe's Jev (US-hosted); without a key only quote matching runs.

## Install

See the README: a virtual environment, then one `pip install` from GitHub. Python 3.11+.

Full list of changes and the bugs found during release hardening: [CHANGELOG.md](../CHANGELOG.md).
