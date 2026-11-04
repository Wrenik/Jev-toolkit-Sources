# jev-sources: source restriction

> **State note (for the next run):** steps 1-8 are built and committed locally; nothing is pushed. Not done: a Claude Code skill wrapper around `python -m jev_sources prompt` (paste it instead), an HTML report (the output is plain text and JSON), a search provider for the pre-filter (it filters results you give it), per-jurisdiction tagging of individual documents inside a set.

> **Read this first.**
> * It checks what each claim **cites** against a policy file you control, and it checks that the cited quote exists and supports the claim ([Jev-toolkit-FactCheck](https://github.com/Wrenik/Jev-toolkit-FactCheck)'s machinery). It **cannot prove the model did not use other knowledge.** A claim with no source is flagged `untraceable`, never approved; a claim that cites an approved page the model did not really use looks identical to a faithful one.
> * The **hook only sees tool calls** (WebFetch, WebSearch). It cannot see Bash/curl, model memory, or redirects that the WebFetch tool follows itself. Redirects are only caught after the fact by `check`, or by `jev_sources fetch` (which checks every hop before connecting).
> * The test scenarios are **hand-written, invented and by the same author as the code** (46 scenarios: 26 dev, 20 held-out). Numbers are in "Evaluation", including the failures and the first-run held-out result before any fix.
> * A domain on the allowlist is trusted as a whole. If an approved site hosts user-written pages, the policy cannot tell them apart unless you add path prefixes.

> **Privacy position.** The only text that can go to TypeSafe's Jev (a US-hosted service whose data-processing location is not yet verified, see the Jev-toolkit-usage README) is: for approved claims whose quote was found, the claim, the quote and a bounded, redacted window around the matched passage (as in Jev-toolkit-FactCheck); and, only with `--classify`, a redacted excerpt of at most 1500 characters of an untagged source. **Never sent:** the policy, rule ids, URLs, the answer text, anything about forbidden sources. All policy decisions are deterministic code. Jev is used only because it is the only typed-answer judgement model today; the plan is a local or EU model behind the same `Judge` interface (`jev_core`). This package never imports the TypeSafe SDK.

## Try it (offline, no key, about 2 seconds)

```bash
python -m jev_sources demo                  # invented sites + fake web, one round, shows what the model is told
python -m jev_sources validate --policy src/jev_sources/evalset/policy.toml
python -m jev_sources eval                  # dev + held-out, word-overlap baseline judge
python -m jev_sources prompt                # the instructions to paste into Claude Code
```

Real use: copy `src/jev_sources/evalset/policy.toml` to `$JEV_HOME/var/sources-policy.toml` (default `~/.jev-toolkit/var/`; `python -m jev_sources prompt` prints the exact path), replace the rules, run `validate`, then use `prompt`, `check`, and (optionally) the hook below.

## What it does

```
before the model sees anything                       after it answers
  retrieval results --> `filter` --> approved only     claims.json (claim, url, VERBATIM quote)
  a page to read    --> `fetch`  --> approved only            |
  WebFetch/WebSearch --> hook (monitor | enforce)             v
                                                      1. each cited URL judged by the policy (no network)
policy.toml (versioned, TOML)  ------------------->   2. forbidden -> state forbidden_source, NOT fetched
  allow / deny / docsets+sha256 / jurisdictions       3. no url/quote -> state untraceable
                                                      4. approved -> jev_factcheck: fetch (every hop checked),
                                                         quote match, judge (Jev via Judge) support
                                                      5. failures -> corrections.json, round cap 3, tool counts
```

Each claim ends in one of: `supported`, `quote_only` (judge off or down), `not_supported` (approved source, but it does not support the claim; if the passage lacks the information the loop stops and the answer must say the approved sources do not cover it), `quote_not_found`, `source_unavailable`, and the two new ones: **`forbidden_source`** (names the rule, says what is allowed) and **`untraceable`**.

## The policy file (`policy.toml`)

Human-readable TOML (stdlib `tomllib`, comments allowed, diff-friendly). Versioned: `[policy].version` must have a `[[changelog]]` entry or the file is invalid.

```toml
[policy]
name = "employer-and-swedish-law"
version = "1.2.0"
jurisdictions = ["SE"]          # optional: allow rules tagged with another jurisdiction are switched off
# allow_archives = false        # default: archive/cache/translate copies are rejected
# web_search = "block"          # what the hook does with WebSearch (it cannot filter search results)

[[changelog]]
version = "1.2.0"
date = "2026-11-03"
note = "Added the HR handbook."

[[allow]]
id = "law-se"
host = "lagen.example"
subdomains = true
jurisdiction = "SE"

[[allow]]                        # path-aware: /lagstiftning, not /lagstiftningar
id = "gov-se"
prefix = "https://gov.example/lagstiftning"
jurisdiction = "SE"

[[allow]]
id = "hr-docs"
docset = "hr"

[[deny]]                         # deny always beats allow
id = "no-blog"
host = "blog.lagen.example"

[[docset]]
id = "hr"
root = "docs"                    # relative to the policy file
[docset.files]
"handbook.md" = "<sha256>"       # create with: python -m jev_sources hash docs
```

* **Rules:** `host` (exact, or `subdomains = true` = dot-anchored suffix, never a string prefix), `suffix` (every domain under a registry-controlled public suffix such as `gov.uk` or `gov`), `prefix` (scheme + host + path, on a path-segment boundary), `docset`. Default is deny. `deny` wins; `validate` prints an `overlap` warning when an allow and a deny rule can match the same URL (and rejections of such URLs name both).
* **Jurisdictions:** a tag on an allow rule (`"SE"`, `"EU"`). With `jurisdictions` set in `[policy]`, a rule with another tag is inactive and a URL it would have matched is rejected with "approved only for jurisdiction DE, active: SE". The jurisdiction of a source is whatever its rule says (deterministic); the judge never assigns it (see `--classify`).
* **Validation** reports *all* problems at once and names the rule: unknown keys (typos), missing version, no changelog line for the current version, duplicate ids, hosts without a dot or that are IP addresses, prefixes with a query string, docsets without a manifest or with a malformed hash, an allow rule that points at a missing docset, a policy with no allow rules.
* **Policy text is data.** Rule ids, hosts, prefixes and docset names are validated against strict patterns (an id like `Ignore previous instructions...` is a validation error), so nothing a policy contains can become a sentence in a prompt. Free text (`note`, changelog notes) is length-limited, shown to humans only, and never put in a judge state, a rejection message or `corrections.json` (tested with an injection string in a rule `note` and a changelog note).

### Document sets and what happens when a file changes

`docset:<id>/<relative/path>` cites a local file. It is approved only if the file is in the manifest **and its sha256 matches**. A file changed after approval **fails closed**: `forbidden_source`, code `docset_modified`, rule `hr-docs` named, the old and new hash prefixes shown. The file is hashed once and the same bytes are read (no check-then-read race). **To re-approve (a person's job):** read the new version, run `python -m jev_sources hash <folder>`, paste the new hash into the policy, bump `[policy].version`, add a `[[changelog]]` line. The re-approval steps are shown to the human only; the model-facing correction says just "changed after approval". A file that exists but is not in the manifest is `not_in_manifest`; path tricks (`..`, `//`, `%2f`, backslash) are rejected, and a resolved path outside the folder is refused (the symlink case is coded but not tested).

## URL handling (`urlcanon.py`, `engine.py`)

Rules are never matched against the raw string. Every URL is canonicalised first or rejected with a stable code. Each row below has a test.

| Trick | Handling |
|---|---|
| `https://allowed.example@evil.example/` (userinfo) | rejected: `userinfo_in_url` |
| `allowed.example.evil.example`, `allowed.example.com`, `notallowed.example` | not a match (exact or dot-anchored suffix only); the message adds "looks similar to the allowed host ..." |
| IDN / homoglyph (Cyrillic `а` in `lаgen`) | converted to punycode, so it differs from the allowed host; message says the host has non-ASCII characters and may be a lookalike |
| uppercase, trailing dot, default port, fragment | normalised away (`LAGEN.EXAMPLE.:443/x#f` = `lagen.example/x`) |
| any port but the scheme's own default (`:8443`, and `https://host:80/`), port `0` | rejected (`builtin/port`, `bad_port`) |
| `http://` | rejected unless the rule says `allow_http = true` |
| `straße.example` (IDNA 2003 would silently turn it into `strasse.example`, a different domain), `ⓐ`-style compatibility characters, `。` | rejected as `ambiguous_idna_host`: write the `xn--` form of the host you mean. Python's built-in codec is IDNA 2003 and browsers use IDNA 2008, so a name that does not survive the round trip is refused instead of guessed |
| `/private;jsessionid=1` against a deny on `/private` | deny rules ignore `;parameters` on each path segment (Tomcat and others serve it as `/private`) |
| `/private%00` | rejected: a percent-encoded control character in the path |
| more than one trailing dot (`host..`) | rejected as malformed (one trailing dot is the DNS root and is dropped) |
| `/law` vs `/lawyer`, `/law/../private` | prefix match is on a path-segment boundary after dot-segment resolution; the bare `/law` (no trailing slash) is deliberately treated as the directory itself and matches prefix `/law/` |
| `/Private/` vs deny prefix `/private/` | **deny** rules compare paths case-insensitively (IIS, Windows and some CMSs serve both as one resource, so case must not bypass a deny); **allow** rules stay case-exact, so a wrong-case URL is simply not approved |
| `%2e%2e`, `%252e`, `%2f`, `%5c`, backslash | dots decoded then resolved; encoded slashes/backslashes rejected (ambiguous) |
| `javascript:`, `data:`, `file:`, `ftp:`, `//host` | rejected: not a source |
| IP literals, `2130706433`, `0x7f.1`, `[::1]` | rejected |
| open redirector on an approved host (`/r?url=https://evil...`) | a URL found in a query value must itself pass; otherwise rejected before any connection |
| real redirect from an approved page to a forbidden one | every hop is judged: the host before DNS, the full URL before the connection, so the forbidden site is **not contacted** (tested); the chain is judged again after the fetch, which also covers cached results |
| archive / cache / translate / proxy / shortener (web.archive.org, archive.ph, webcache, translate.goog, bit.ly, ...) | rejected (`builtin/wrapper`: "cite the original page"); with `allow_archives = true` the wrapped URL must itself pass |
| mirrors | a mirror is just another host: not listed = rejected; use `canonical = "..."` in a rule to document the original. The tool does not detect copies of content |

### Public suffixes and user-content hosts (policy-writing time)

`subdomains = true` on `github.io`, `blogspot.com`, `herokuapp.com` and similar multi-tenant suffixes is refused when the policy is loaded: it would approve every customer of that service. A rule on a registry-style suffix (`co.uk`, `com.au`) and a bare host rule on a user-content platform (`github.com`, `medium.com`, `reddit.com`) produce a `public-suffix:` / `user-content:` warning in `validate`. This uses a bundled snapshot of the Public Suffix List's ICANN section (`src/jev_sources/data/public_suffix_icann.dat`, dated in its header, regenerated by `tools/update_suffixes.py`) plus a short hand-made list of private multi-tenant platforms, so it is a guard rail, not a guarantee; it never changes how a URL is judged. To approve a registry suffix on purpose, write `suffix = "gov.uk"`: it covers every domain registered under that suffix (not the suffix itself), must be a real ICANN suffix, and always produces a `broad:` warning.

### Where the semantics come from (and differ)

See [PRIOR_ART.md](PRIOR_ART.md) for what was actually read in round 2. Earlier note, written from memory: Content-Security-Policy host sources ignore query and fragment, treat a path ending in `/` as a prefix, and let `*.example` match subdomains but **not** the apex (here `subdomains = true` includes the apex; the rule text says "and its subdomains"). Claude Code's `WebFetch(domain:...)` permission rules match a domain, with deny taking priority over allow. Cedar and OPA both default to deny and let a forbid/deny override a permit/allow, which is the rule here; OPA's decision logs inspired `explain` (a decision should be inspectable). The `explain` Decision line is the engine's own answer; its per-rule lines reuse the engine's matcher, so the two cannot disagree.

## Enforcement before the model sees anything

1. **`python -m jev_sources filter results.json`**: keeps approved results, drops the rest. What the model receives about removed results is **only a count** (no title, URL or snippet); the per-result rule goes to `var/sources-filter-log.jsonl` for you. It filters what you pass in: this repo has no search provider.
2. **`python -m jev_sources fetch <url|docset:..>`**: the page-reading path the prompt tells the agent to use. Approved: text. Not approved: the refusal naming the rule and what is allowed. Every redirect hop is checked.
3. **Claude Code hook (monitor by default).** Add to `.claude/settings.json`:

```json
{"hooks": {"PreToolUse": [{"matcher": "WebFetch|WebSearch",
   "hooks": [{"type": "command", "command": "python -m jev_sources hook --policy ~/.jev-toolkit/var/sources-policy.toml"}]}]}}
```

   Default is **monitor**: it logs to `$JEV_HOME/var/sources-hook.jsonl` (query strings stripped) and lets the call through, printing a one-line `[monitor] ... would block ...` with the rule and how to allow once. Tools that block without warning get switched off, so enforcement is an explicit switch: add `--enforce` (or set `JEV_SOURCES_MODE=enforce`). In enforce mode a blocked call exits 2 with one line: `Blocked by source policy <name> v<version>. Rejected by rule <id>: ... Allowed instead: ... A person can allow this once with: python -m jev_sources allow-once <url>`. If the policy file cannot be loaded, enforce mode blocks all web access (fail closed) and monitor mode lets calls through. WebSearch cannot be filtered, so with `web_search = "block"` it is blocked in enforce mode.
   **Allow once** is for a person: it asks for typed confirmation on a terminal and refuses to run from a script or an agent; a grant covers one access within 10 minutes. This is a guardrail against drift, not a defence against an agent that may edit its own settings and policy files: deny it `Edit`/`Write` on `.claude/settings.json`, `var/sources-*` and the policy file in your Claude Code permissions.
   **Verified:** hook input/exit-code behaviour, monitor vs enforce, allow-once consumption and expiry, bad-policy fail-closed (unit tests). **Not verified:** a live Claude Code session end to end with the hook installed.

## Enforcement after it answers: `check`

```bash
python -m jev_sources check claims.json --policy ~/.jev-toolkit/var/sources-policy.toml --state state.json   # [--classify] [--no-judge]
```

Same `claims.json` contract as Jev-toolkit-FactCheck (no Anthropic API key; the LLM in your Pro session writes it, following `python -m jev_sources prompt`). Differences: a claim with no `url` or no `quote` is kept and marked `untraceable` (Jev-toolkit-FactCheck would reject the whole file). Forbidden claims are **never fetched**. The summary reports sentences of the answer that no claim covers ("N sentences have no claim and were NOT checked"). Exit 0 when everything is supported, 1 when something is flagged, 2 for a bad file or policy.

**Rewrite loop** (Jev-toolkit-FactCheck's `loop.advance`, round cap 3 counted by the tool). `corrections.json` lists each open claim with `rule`, `allowed_instead` and an instruction, plus a fixed note: cite only from the allowed sources; if none contains the information, say so; no memory; no other sources; do not suggest changing the policy. A claim stops being retried when it is fixed, when the same URL and quote come back, when the approved source lacks the information (then only retract / "not covered by the approved sources"), or at the round cap. The tool never relaxes the policy and never proposes a new source.

## What the judge (Jev) is and is not used for

* **Deterministic, no judge:** every allow/deny decision, hashes, URL tricks, untraceable-by-missing-fields, the round cap, the rule named in each rejection.
* **Jev, reused from Jev-toolkit-FactCheck:** does the quote in an *approved* page support the claim (relation + "out of context" question). Judge down: `quote_only`; it never turns a forbidden or untraceable claim into anything else.
* **Jev, new and optional (`--classify`):** for an approved source whose rule has no jurisdiction tag, while the policy restricts jurisdictions, classify the excerpt (`SE` / `other` / `unclear`). The result can only add a **flag** (`jurisdiction_mismatch:other`) with its probability; it never approves or rejects. Injection-like excerpts are not sent.
* **Not used for traceability.** "Is this claim from memory?" is not something a judge can know; the only evidence is a missing or non-quoting citation. See limits.

## Evaluation

**Data** (`src/jev_sources/evalset/`): an invented policy (`policy.toml`, 5 allow rules incl. a path prefix, a docset and an inactive-jurisdiction rule, 2 deny rules), invented ".test" sites on a fake web (`FakeWeb`, which exercises the *real* fetcher, redirect and hop-check code), 4 local documents. **dev** = 26 (22 scenarios + 4 malformed policies), written while building; **held-out** = 20 (16 + 4), written after the rules were frozen and committed *before its first run*. Categories: approved cited correctly, forbidden cited, lookalike (4 forms dev, 2 held-out), redirect (redirect to forbidden domain, open redirector, archive/cache/translate wrappers, percent-encoded path, redirect within an approved site that must pass), untraceable (no source; made-up "source"; empty quote), approved source insufficient/contradicting, policy overlap (allow+deny), malformed policy, docset hash changed / not in manifest. Scenarios also assert that forbidden hosts were **never contacted or resolved**.

| | dev (26) | held-out (20) |
|---|---|---|
| **first run**, word-overlap baseline judge | 25/26 | **18/20** (before any fix) |
| after harness fix, baseline | 25/26 | 19/20 |
| Jev jev-1.14.0 (`eval --live`) | 26/26 | 20/20 |
| policy layer (deterministic) | 15/15 | 12/12 |
| judge layer: baseline / Jev | 6/7, 7/7 | 3/4 (first run 2/4), 4/4 |

* **First held-out run, before any fix: 18/20.** Failures: **h02** (`https://LAGEN.TEST/semester#top` came back `source_unavailable`): a bug in my *fake web*, which looked pages up by the raw string; the policy decision was right. Fixed (fixtures keyed by canonical URL), committed separately; this is a harness fix, not a rule change. **h16** (claim "40 days ... at the manager level" vs a quote saying 25 days) judged "supports" by the word-overlap baseline because most words overlap: the baseline is dumb on changed numbers, same as in Jev-toolkit-FactCheck.
* **Dev failure kept:** d20 (claim says 240 days, quote says 480) the baseline judges "supports". Jev got it right.
* **Jev was run on both sets after the held-out first run and the harness fix**, once each: 26/26 and 20/20. That is not a clean blind run for the held-out set (the baseline result had been seen), and the rules/engine were not changed in between.
* **What 100% does not mean.** 46 hand-written scenarios, invented content, one author who also wrote the rules. The policy layer's 27/27 is mostly because each scenario was written to hit a rule that exists; real policies, real redirects, real pages and real attackers are messier. A 20/20 result has a 95% lower bound near 84% (Wilson). The unit tests (`tests/test_sources_*.py`) add many URL-form cases beyond the scenario sets, including a ~75-row trick list (`tests/test_sources_tricks.py`) probed against the engine once before it was fixed; the fixes it forced (port 80 on https, `:0`, IDNA 2003 `ß`, `;param` and `%00` against a deny) are listed in the CHANGELOG.
* **Not measured:** real websites, real Claude Code sessions with the hook, how often a model works around a policy, non-English sources, large policies, cost over many claims, a determined adversary who knows the policy.

## Known limits (please read)

* **Untraceable claims.** A claim without source or quote is flagged `untraceable` and sent back; it is never approved. But if the model attaches an approved URL and a real quote to a claim it actually took from memory, the tool cannot tell. Quote existence + the judge's support check make this harder, not impossible. Sentences with no claim are only counted, not checked.
* **Citations are checked, not the model's knowledge.** The model may have used other information and then cited an approved page that happens to agree.
* **The hook sees tool calls only**: no Bash/curl, no MCP tools you did not list in the matcher, no redirects followed by WebFetch itself, no memory. Enforcement of "the agent must use `jev_sources fetch`" rests on the prompt plus the hook; it is not a sandbox. An egress firewall is the real boundary.
* **Domain trust is coarse.** Allowing a domain allows everything on it (forums, user uploads) unless you use prefixes. Open-redirector and wrapper detection is a list of known patterns, not a proof that no redirector exists on an approved site; redirects that really happen are caught per hop only when fetched through `jev_sources`.
* **Archive and mirror copies are rejected by default**, which also rejects legitimate archived copies of approved pages; `allow_archives` is the (coarse) switch.
* **Hashes pin bytes, not meaning**: any edit (even a typo fix) fails closed until re-approved. That is the intended trade.
* **Policy conflicts:** deny wins and is warned about, but overlapping `prefix` and `host` rules are only compared at host/path level, not for every possible URL.
* Paywalled, script-rendered and PDF pages are `source_unavailable`, as in Jev-toolkit-FactCheck. The fetcher is Jev-toolkit-FactCheck's (no robots.txt check).
* The judge is probabilistic; support is a probability, not a proof.

## Why Python

`jev_core` (Judge, cache, logging, redaction) and `jev_factcheck` (claims, quote matching, safe fetcher, correction loop) are Python and are imported as they are, so there is no glue. The work is I/O-bound and small; the standard library supplies `tomllib`, `urllib.parse`, IDNA, `hashlib` and the pieces needed to apply a policy on every redirect hop. Rust would give a single static binary and memory safety for hostile HTML/PDF, which matters if the URL-policy and fetch layer ever runs as a service or a proxy in front of an agent; the policy engine (`urlcanon.py`, `engine.py`) has no dependencies and is the part to port first.

## Prior art

Links come from search results and my own knowledge of the field; I read summaries, advisories and tool descriptions, not every README or paper in full. Check a tool's current state before relying on this.

* **Allowlists for agents and what goes wrong.** PromptArmor on [which domains to put on an agent allowlist](https://www.promptarmor.com/resources/what-domains-should-i-add-to-my-allowlist) (an allowed domain is trusted under prompt injection: the same limit applies here). A [2026 advisory for an MCP docs fetcher](https://api.osv.dev/v1/vulns/CVE-2026-46341) bypassed by `startsWith` prefix checks and `allowed.com@evil.com` forms (hence parsed-host comparison and userinfo rejection here). [Guarding against URL-based exfiltration](https://agentpatterns.ai/security/url-exfiltration-guard/): follow redirects manually and check every hop (done here, before connecting). An [OpenClaw pull request](https://github.com/openclaw/openclaw/pull/19042) applies a web_fetch allowlist to redirect targets. [agentguard-rs](https://dev.to/mukundakatta/agentguard-rs-domain-allowlists-for-rust-ai-agent-network-calls-2bke): domain allowlists for agent network calls.
* **RAG governance.** Vendor and practitioner write-ups ([Gravitee on agentic RAG governance](https://gravitee.io/corpus/gen-1006/get-a-wiggle-on/agentic-rag-governance-securing-retrieval-citation-and-knowledge-source-access-for-ai-agents.html), the R package [llmshieldr](https://cran.nics.utk.edu/cran/web/packages/llmshieldr/vignettes/rag-pipeline.Rmd)) describe the same pattern: governed source allowlist, abstain when no approved source fits, check claims against cited passages, audit log. No standard specifies it. llmshieldr, per its documentation, *flags* sources outside `trusted_sources` instead of blocking them; this tool blocks.
* **From my own knowledge (not re-read for this doc):** metadata filters in RAG frameworks (LlamaIndex, LangChain retrievers) restrict what is retrieved but not what the model then cites; NVIDIA NeMo Guardrails and Guardrails AI run rails/validators on model output; Open Policy Agent / Cedar are general policy-as-code engines that could host the allow/deny rules; Claude Code's own `WebFetch`/`WebSearch` permissions and `allowed_domains` limit domains but do not see redirects, do not tie a citation to a rule, and cannot ask for a rewrite; [Claude Code hooks](https://docs.claude.com/en/docs/claude-code/hooks) are the extension point used here.
* **Jev-toolkit-FactCheck ([Jev-toolkit-FactCheck](https://github.com/Wrenik/Jev-toolkit-FactCheck), docs/FACT_CHECKER.md):** the claim/quote/fetch/match/verdict/loop modules are reused unchanged through their public functions; Jev-toolkit-FactCheck only *flags* unusual domains, this project *fails* them.
* **What differs here.** Policy is a versioned, validated, human-readable file with deny rules, path-aware prefixes, hash-pinned document sets and jurisdiction tags; every rejection names the rule that failed and what would be allowed; enforcement happens before retrieval results reach the model (filter/fetch/hook) and after the answer (citation check), with forbidden sources never contacted, even through redirects; URL tricks (lookalikes, userinfo, wrappers, open redirectors, encoding) are handled and tested explicitly; untraceable claims are a named state, not silently passed; policy text can never become model instructions; the rewrite loop has hard stop rules and says "the approved sources do not contain this" rather than relaxing the policy; the hook defaults to monitor mode; everything runs inside a Claude Code subscription session with no Anthropic API key.
