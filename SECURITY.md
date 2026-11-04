# Security policy

This is an experimental learning project about restricting where an answer may get its sources. It is **not a security product**: read "Limits" in [docs/SOURCE_RESTRICTION.md](docs/SOURCE_RESTRICTION.md) before relying on it (it cannot prove a model did not use other knowledge; the hook only sees tool calls).

## Reporting a problem

* A **URL the policy wrongly allows** (a lookalike host, an encoding trick, a redirect or wrapper that gets past the rules) is welcome as a normal issue, with an inert example (`.test`/`.invalid` hosts, no real secrets). It is exactly the feedback this project wants.
* A vulnerability in the code itself that you would rather not describe publicly: use GitHub's **private vulnerability reporting** (the repository's Security tab). If that button is missing, open an issue that says only that you have a security report, without details.
* Bugs in the shared fetcher or checker belong to [Jev-toolkit-FactCheck](https://github.com/Wrenik/Jev-toolkit-FactCheck); redaction and the judge layer to [Jev-toolkit-usage](https://github.com/Wrenik/Jev-toolkit-usage).

## Scope

In scope: the Python package in `src/` and the claims in the documentation. Out of scope: TypeSafe's service, Claude Code, and attackers who already control your machine or your policy file (policy files are data you trust).

## Threat model: what enforcement can and cannot prove

Assumed attacker: text the model reads (pages, search results, documents) and the model's own mistakes, trying to get an answer backed by a source the policy does not approve. The policy file, the machine and the Python environment are trusted.

Enforced (deterministic, offline, tested): default deny; deny beats allow; one canonical URL form before any rule (userinfo, lookalike and Unicode hosts, IP forms, encodings, dot segments, invisible and bidi characters, wrappers, open redirectors in query strings); the policy is applied before DNS and before the connection on every redirect hop; document sets are pinned by sha256 and must resolve inside their folder (symlinks that leave it are refused).

Not provable:

* **Memory.** The model can use knowledge from training and merely cite an approved URL. `check` verifies that the quote exists in the approved page and (optionally) that a judge rates it as supporting; it cannot show the claim came from there. Sentences with no claim are reported as unchecked, not blocked.
* **Hook coverage.** The hook sees tool calls, not what a Bash command or an MCP server fetches internally; pair it with the sandbox network allowlist (docs/PRIOR_ART.md).
* **Content, not just origin.** An approved host can serve wrong, changed or user-written text (`user-content:` warns, `prefix` narrows). Docset hashes catch edits only after approval.
* **Network layer.** DNS rebinding between check and connection is narrowed by FactCheck's resolver pinning, not eliminated; a compromised approved host, a CDN serving different content and TLS interception are out of scope.
* **Parser differences.** The canonical form is ours; a server or proxy that parses differently can still disagree. Ambiguous input is rejected rather than interpreted, which reduces but does not remove this.
* **Public Suffix List age.** The bundled snapshot is dated and only informs policy writing; the PRIVATE section is approximated by a short list. A `suffix =` rule is a deliberate broad approval.
* **The judge** is a model: its verdict is a flag, never a proof.

## Secrets

Never put your `TYPESAFE_API_KEY` in an issue, a log excerpt or a policy file. `.env` and `var/` are git-ignored; by default data is kept outside any repository in `~/.jev-toolkit` (`JEV_HOME`).
