# Jev-toolkit-Sources

[![tests](https://github.com/Wrenik/Jev-toolkit-Sources/actions/workflows/tests.yml/badge.svg)](https://github.com/Wrenik/Jev-toolkit-Sources/actions/workflows/tests.yml)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![status](https://img.shields.io/badge/status-alpha-orange)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Source restriction:** an answer may only be backed by sources on an allowlist **policy** you write and version (a plain TOML file). Like [Jev-toolkit-FactCheck](https://github.com/Wrenik/Jev-toolkit-FactCheck), a claim fails if its verbatim quote is not in its source or does not support it, but it also **fails if its source is not on the policy**. The policy is enforced twice: before the model sees retrieval results (`filter`, `fetch`, an optional Claude Code hook) and after it answers (`check`). Every rejection names the rule and what would have been allowed. If the approved sources do not contain the answer, the tool says so; it never relaxes the policy. The rewrite loop is hard-capped at 3 rounds.

Depends on [Jev-toolkit-FactCheck](https://github.com/Wrenik/Jev-toolkit-FactCheck) (claims, quote matching, safe fetcher, correction loop) and [Jev-toolkit-usage](https://github.com/Wrenik/Jev-toolkit-usage) (the `Judge` interface, cache, redaction, data location).

## Status and limits

* It checks what each claim **cites** against the policy. It **cannot prove the model did not use other knowledge**; a claim with no source is flagged `untraceable`, never approved.
* The hook only sees Claude Code's WebFetch/WebSearch calls, not Bash/curl or model memory. It starts in **monitor** mode (logs and warns); `--enforce` or `JEV_SOURCES_MODE=enforce` blocks.
* A domain on the allowlist is trusted as a whole unless you add path prefixes. Policy files are data you trust.
* The 46 test scenarios (26 dev, 20 held-out) are hand-written and invented by the author of the code: not evidence of real-world accuracy. The first held-out run, before any fix, was 18/20; the failures are listed in [docs/SOURCE_RESTRICTION.md](docs/SOURCE_RESTRICTION.md).

## Install

Want all six tools? Use [the install script](https://github.com/Wrenik/Jev-toolkit-usage/blob/main/docs/INSTALL_ALL.md) (`scripts/install_all.ps1` or `.sh` in Jev-toolkit-usage) instead of the steps below.

Requires Python 3.11+. Make the virtual environment **outside** any clone (or anywhere you like):

```bash
python -m venv ~/jev-venv
# Windows: ~/jev-venv/Scripts/python   Linux/macOS: ~/jev-venv/bin/python
PY=~/jev-venv/Scripts/python
$PY -m pip install "git+https://github.com/Wrenik/Jev-toolkit-Sources.git"   # also installs FactCheck and usage
$PY -m jev_sources demo
```

Data (logs, cache, your default policy file) lives in `JEV_HOME` (default `~/.jev-toolkit`, under `var/`); a `.env` with `TYPESAFE_API_KEY` there is only needed for the real judge. CI checks out both dependency repos and installs them editable.

## Quick try (offline, no key)

```bash
python -m jev_sources demo        # invented sites + fake web: a forbidden source, a redirect, a changed document, memory, one rewrite round
python -m jev_sources eval        # dev + held-out sets with the word-overlap baseline judge
python -m jev_sources prompt      # the instructions to paste into Claude Code
```

## Write your own policy (5 minutes)

```bash
python -m jev_sources init docs-only --out policy.toml     # or gov-sources, or: offline-corpus --docs ./my-notes
python -m jev_sources validate --policy policy.toml        # every problem at once, naming the rule; warnings for risky rules
python -m jev_sources explain "https://docs.python.org/3library/x" --policy policy.toml
python -m jev_sources fetch  "https://docs.python.org/3/library/json.html" --policy policy.toml
```

`explain` never touches the network. It shows the canonical form of the URL, which rules matched and why the others did not, and the decision:

```
Input:      https://docs.python.org/3library/x
Canonical:  https://docs.python.org/3library/x
Rules:
  no match deny  no-changelog: URLs under https://docs.python.org/3/whatsnew/changelog/  (path /3library/x is not under /3/whatsnew/changelog ...)
  no match allow python-docs: URLs under https://docs.python.org/3/  (path /3library/x is not under /3 (a prefix matches whole path segments only))

Decision:   REJECTED by builtin/default-deny
            Rejected by rule builtin/default-deny: docs.python.org is not on the allowlist (default is deny); the host docs.python.org has approved path prefixes, but this path is under none of them. Allowed instead: ...
```

Starter policies are in `src/jev_sources/templates/` (`docs-only`, `gov-sources`, `offline-corpus`). The policy format, URL handling, the hook and the evaluation: [docs/SOURCE_RESTRICTION.md](docs/SOURCE_RESTRICTION.md). Release history: [CHANGELOG.md](CHANGELOG.md).

## End to end with FactCheck

`python examples/end_to_end.py report.html` runs a four-claim `claims.json` through the policy-guarded fetcher and FactCheck's renderer, offline; the claim that cites a denied forum is rejected, never contacted, and the report names the rule `no-forums`. See [docs/END_TO_END.md](docs/END_TO_END.md) and the saved [report](docs/end_to_end_report.html). Research behind the design: [docs/PRIOR_ART.md](docs/PRIOR_ART.md).

## Privacy

With the judge on, per claim whose quote was found in an *approved* source, the claim, the quote and a bounded, redacted window of the matched passage go to **TypeSafe's Jev**, a US-hosted service whose data-processing location is not verified. With `--classify`, also a redacted excerpt of at most 1500 characters of an untagged source. Never sent: the policy, URLs, the answer. **Jev is used because, as of today, it is the only model of its kind on the market, not because sending data to a US company is the goal. The plan is to replace it with a local model or a European provider** through the `Judge` interface in `jev_core`; this package never imports the TypeSafe SDK. Without a key the tool falls back to quote matching only. The tool contacts the approved websites you cite, from your machine, and never a forbidden host.

## Prior art

See [docs/PRIOR_ART.md](docs/PRIOR_ART.md): related tools, what they do, and what differs here. Nothing is copied from them.

## The Jev toolkit family

| Repository | What it is | Depends on |
|---|---|---|
| [Jev-toolkit-usage](https://github.com/Wrenik/Jev-toolkit-usage) | `jev_core` (judge interface, Jev adapter, cache, decision log, redaction, settings and data location) and the model/effort router | - |
| [Jev-toolkit-Compiler](https://github.com/Wrenik/Jev-toolkit-Compiler) | context log, search and a compact/clear advisor | usage |
| [Jev-toolkit-Scanner](https://github.com/Wrenik/Jev-toolkit-Scanner) | prompt-injection scanner (experimental) | usage |
| [Jev-toolkit-Monitor](https://github.com/Wrenik/Jev-toolkit-Monitor) | agent monitor (experimental) | usage |
| [Jev-toolkit-FactCheck](https://github.com/Wrenik/Jev-toolkit-FactCheck) | fact checker with hover evidence | usage (Scanner optional) |
| **Jev-toolkit-Sources** (this one) | source restriction (allowlist policy) | usage, FactCheck |

All six on one machine: [docs/INSTALL_ALL.md](https://github.com/Wrenik/Jev-toolkit-usage/blob/main/docs/INSTALL_ALL.md) (a script does it). All six repositories are public.

## Contributing, security, license

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). URL bypasses and wrong rejections (with inert examples) are the most useful reports.

Licensed under the [MIT License](LICENSE).
